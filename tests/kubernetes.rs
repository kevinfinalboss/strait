//! Discovery against a real cluster. Needs a kubeconfig, for example from kind:
//!
//!     kind create cluster
//!     cargo test --test kubernetes -- --ignored
//!
//! The test creates EndpointSlices directly, so no pods or images are needed.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointPort, EndpointSlice};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{DeleteParams, PostParams};
use kube::{Api, Client};
use prometheus_client::registry::Registry;
use strait::{Config, Metrics, Server};
use tokio::time::{sleep, timeout};

fn endpoint(ip: &str, ready: bool) -> Endpoint {
    Endpoint {
        addresses: vec![ip.into()],
        conditions: Some(EndpointConditions {
            ready: Some(ready),
            ..EndpointConditions::default()
        }),
        ..Endpoint::default()
    }
}

fn slice(name: &str, endpoints: Vec<Endpoint>) -> EndpointSlice {
    EndpointSlice {
        metadata: ObjectMeta {
            name: Some(name.into()),
            labels: Some([("kubernetes.io/service-name".into(), "web".into())].into()),
            ..ObjectMeta::default()
        },
        address_type: "IPv4".into(),
        endpoints: Some(endpoints),
        ports: Some(vec![EndpointPort {
            name: Some("http".into()),
            port: Some(8080),
            protocol: Some("TCP".into()),
            ..EndpointPort::default()
        }]),
    }
}

/// Backend addresses strait currently has for the listener, read from its metrics.
fn backends(registry: &Registry) -> Vec<String> {
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, registry).unwrap();
    let mut found: Vec<String> = text
        .lines()
        .filter(|line| line.starts_with("strait_backend_up{"))
        .filter_map(|line| line.split("backend=\"").nth(1)?.split('"').next())
        .map(str::to_owned)
        .collect();
    found.sort();
    found
}

async fn eventually(registry: &Registry, expected: &[&str]) {
    let result = timeout(Duration::from_secs(20), async {
        while backends(registry) != expected {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "backends are {:?}, expected {expected:?}",
        backends(registry)
    );
}

#[tokio::test]
#[ignore = "needs a Kubernetes cluster"]
async fn follows_endpointslice_changes() {
    let client = Client::try_default().await.expect("no Kubernetes cluster");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let namespace = format!("strait-test-{suffix}");

    let namespaces: Api<Namespace> = Api::all(client.clone());
    let ns = Namespace {
        metadata: ObjectMeta {
            name: Some(namespace.clone()),
            ..ObjectMeta::default()
        },
        ..Namespace::default()
    };
    namespaces
        .create(&PostParams::default(), &ns)
        .await
        .unwrap();
    let slices: Api<EndpointSlice> = Api::namespaced(client, &namespace);

    // One ready and one not-ready endpoint: only the ready one is a backend.
    let first = slice(
        "web-a",
        vec![endpoint("10.255.0.1", true), endpoint("10.255.0.2", false)],
    );
    slices.create(&PostParams::default(), &first).await.unwrap();

    let config = Config::parse(&format!(
        "listeners:\n  - name: web\n    listen: 127.0.0.1:0\n    kubernetes: {{service: web, namespace: {namespace}, port: http}}\n"
    ))
    .unwrap();
    let metrics = Arc::new(Metrics::default());
    let server = Server::with_metrics(&config, metrics).await.unwrap();
    let mut registry = Registry::default();
    registry.register_collector(Box::new(server.backend_state()));

    eventually(&registry, &["10.255.0.1:8080"]).await;

    // A second slice for the same service adds its endpoints.
    let second = slice("web-b", vec![endpoint("10.255.0.3", true)]);
    slices
        .create(&PostParams::default(), &second)
        .await
        .unwrap();
    eventually(&registry, &["10.255.0.1:8080", "10.255.0.3:8080"]).await;

    // Deleting a slice removes its endpoints.
    slices
        .delete("web-a", &DeleteParams::default())
        .await
        .unwrap();
    eventually(&registry, &["10.255.0.3:8080"]).await;

    namespaces
        .delete(&namespace, &DeleteParams::default())
        .await
        .unwrap();
}
