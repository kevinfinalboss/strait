//! Backend discovery from Kubernetes EndpointSlices.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use futures_util::StreamExt;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::WatchStreamExt;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client, ResourceExt};
use tokio::task::JoinHandle;
use tracing::{Instrument, Span, info, warn};

use crate::config::{KubernetesBackends, ServicePort};

/// Label that Kubernetes puts on every EndpointSlice of a Service.
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

/// Watches the EndpointSlices of `source` and calls `update` with the full list
/// of ready backends every time it changes. Aborting the task stops the watch.
/// Logs are recorded inside `span`.
pub fn spawn(
    client: Client,
    source: KubernetesBackends,
    span: Span,
    update: impl Fn(Vec<SocketAddr>) + Send + 'static,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let namespace = source
            .namespace
            .clone()
            .unwrap_or_else(|| client.default_namespace().to_owned());
        let api: Api<EndpointSlice> = Api::namespaced(client, &namespace);
        let selector = format!("{SERVICE_NAME_LABEL}={}", source.service);
        let mut events = watcher::watcher(api, watcher::Config::default().labels(&selector))
            .default_backoff()
            .boxed();

        // Slices of the service by name; rebuilt from scratch on every relist.
        let mut slices: BTreeMap<String, EndpointSlice> = BTreeMap::new();
        let mut initial: BTreeMap<String, EndpointSlice> = BTreeMap::new();
        let mut syncing = false;
        let mut current: Option<Vec<SocketAddr>> = None;

        while let Some(event) = events.next().await {
            match event {
                Ok(Event::Init) => {
                    syncing = true;
                    initial.clear();
                }
                Ok(Event::InitApply(slice)) => {
                    initial.insert(slice.name_any(), slice);
                }
                Ok(Event::InitDone) => {
                    syncing = false;
                    slices = std::mem::take(&mut initial);
                }
                Ok(Event::Apply(slice)) => {
                    slices.insert(slice.name_any(), slice);
                }
                Ok(Event::Delete(slice)) => {
                    slices.remove(&slice.name_any());
                }
                Err(err) => {
                    // The watcher retries with backoff; this usually means missing RBAC
                    // or an unreachable API server.
                    warn!(service = %source.service, %namespace, error = %err, "endpoint watch failed");
                    continue;
                }
            }

            // During a (re)list, wait for the full list before publishing anything.
            if syncing {
                continue;
            }

            let backends = ready_backends(slices.values(), &source.port);
            if current.as_ref() != Some(&backends) {
                info!(
                    service = %source.service,
                    %namespace,
                    backends = backends.len(),
                    "kubernetes endpoints updated"
                );
                update(backends.clone());
                current = Some(backends);
            }
        }
    }.instrument(span))
}

/// Ready endpoint addresses of `slices` on `port`, sorted and without duplicates.
///
/// Follows the EndpointSlice rules: an endpoint whose `ready` condition is unset
/// counts as ready, and slices that do not expose the requested port are skipped.
pub fn ready_backends<'a>(
    slices: impl IntoIterator<Item = &'a EndpointSlice>,
    port: &ServicePort,
) -> Vec<SocketAddr> {
    let mut backends = BTreeSet::new();

    for slice in slices {
        if slice.address_type == "FQDN" {
            continue;
        }
        let Some(port) = slice_port(slice, port) else {
            continue;
        };

        for endpoint in slice.endpoints.iter().flatten() {
            let ready = endpoint
                .conditions
                .as_ref()
                .and_then(|conditions| conditions.ready)
                .unwrap_or(true);
            if !ready {
                continue;
            }
            for address in &endpoint.addresses {
                if let Ok(ip) = address.parse::<IpAddr>() {
                    backends.insert(SocketAddr::new(ip, port));
                }
            }
        }
    }

    backends.into_iter().collect()
}

/// Port number in `slice` for `wanted`: matched by name, or used as is when numeric.
fn slice_port(slice: &EndpointSlice, wanted: &ServicePort) -> Option<u16> {
    let ports = slice.ports.as_deref().unwrap_or_default();
    let found = match wanted {
        ServicePort::Name(name) => ports
            .iter()
            .find(|port| port.name.as_deref().unwrap_or("") == name),
        ServicePort::Number(number) => ports
            .iter()
            .find(|port| port.port == Some(i32::from(*number))),
    };
    found
        .and_then(|port| port.port)
        .and_then(|port| u16::try_from(port).ok())
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointPort};

    use super::*;

    fn endpoint(address: &str, ready: Option<bool>) -> Endpoint {
        Endpoint {
            addresses: vec![address.into()],
            conditions: Some(EndpointConditions {
                ready,
                ..EndpointConditions::default()
            }),
            ..Endpoint::default()
        }
    }

    fn slice(address_type: &str, ports: &[(&str, i32)], endpoints: Vec<Endpoint>) -> EndpointSlice {
        EndpointSlice {
            address_type: address_type.into(),
            endpoints: Some(endpoints),
            ports: Some(
                ports
                    .iter()
                    .map(|(name, port)| EndpointPort {
                        name: Some((*name).into()),
                        port: Some(*port),
                        ..EndpointPort::default()
                    })
                    .collect(),
            ),
            ..EndpointSlice::default()
        }
    }

    fn addrs(list: &[&str]) -> Vec<SocketAddr> {
        list.iter().map(|addr| addr.parse().unwrap()).collect()
    }

    #[test]
    fn keeps_ready_endpoints_on_the_named_port() {
        let slices = [slice(
            "IPv4",
            &[("http", 8080), ("metrics", 9090)],
            vec![
                endpoint("10.0.0.2", Some(true)),
                endpoint("10.0.0.1", None),
                endpoint("10.0.0.3", Some(false)),
            ],
        )];

        let backends = ready_backends(&slices, &ServicePort::Name("http".into()));

        assert_eq!(backends, addrs(&["10.0.0.1:8080", "10.0.0.2:8080"]));
    }

    #[test]
    fn matches_a_numeric_port_and_skips_slices_without_it() {
        let slices = [
            slice(
                "IPv4",
                &[("", 5432)],
                vec![endpoint("10.0.0.1", Some(true))],
            ),
            slice(
                "IPv4",
                &[("", 6379)],
                vec![endpoint("10.0.0.9", Some(true))],
            ),
        ];

        let backends = ready_backends(&slices, &ServicePort::Number(5432));

        assert_eq!(backends, addrs(&["10.0.0.1:5432"]));
    }

    #[test]
    fn merges_slices_and_supports_ipv6() {
        let slices = [
            slice(
                "IPv4",
                &[("http", 80)],
                vec![endpoint("10.0.0.1", Some(true))],
            ),
            slice(
                "IPv4",
                &[("http", 80)],
                vec![endpoint("10.0.0.1", Some(true))],
            ),
            slice(
                "IPv6",
                &[("http", 80)],
                vec![endpoint("fd00::1", Some(true))],
            ),
            slice(
                "FQDN",
                &[("http", 80)],
                vec![endpoint("db.example.com", Some(true))],
            ),
        ];

        let backends = ready_backends(&slices, &ServicePort::Name("http".into()));

        assert_eq!(backends, addrs(&["10.0.0.1:80", "[fd00::1]:80"]));
    }

    #[test]
    fn no_slices_means_no_backends() {
        assert!(ready_backends(&[], &ServicePort::Number(80)).is_empty());
    }
}
