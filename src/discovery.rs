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

/// Ready endpoints of a Service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Endpoints {
    /// Every ready address on the wanted port, sorted and without duplicates.
    pub backends: Vec<SocketAddr>,
    /// Ready addresses by the name of the pod behind them (`targetRef`). A
    /// dual-stack pod maps to its lowest address, IPv4 before IPv6.
    pub pods: BTreeMap<String, SocketAddr>,
}

/// Watches the EndpointSlices of `source` and calls `update` with the full list
/// of ready endpoints every time it changes. Aborting the task stops the watch.
/// Logs are recorded inside `span`.
pub fn spawn(
    client: Client,
    source: KubernetesBackends,
    span: Span,
    update: impl Fn(Endpoints) + Send + 'static,
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

        let mut state = EndpointState::default();
        while let Some(event) = events.next().await {
            let event = match event {
                Ok(event) => event,
                Err(err) => {
                    // The watcher retries with backoff; this usually means missing RBAC
                    // or an unreachable API server.
                    warn!(service = %source.service, %namespace, error = %err, "endpoint watch failed");
                    continue;
                }
            };
            if let Some(endpoints) = state.apply(event, &source.port) {
                info!(
                    service = %source.service,
                    %namespace,
                    backends = endpoints.backends.len(),
                    "kubernetes endpoints updated"
                );
                update(endpoints);
            }
        }
    }.instrument(span))
}

/// What the watch has seen of a Service's EndpointSlices.
///
/// Kept apart from the watch itself so the event handling can be tested
/// without an API server.
#[derive(Debug, Default)]
pub struct EndpointState {
    /// Slices of the service by name, as of the last complete list.
    slices: BTreeMap<String, EndpointSlice>,
    /// Slices of a (re)list in progress; replaces `slices` when it completes.
    initial: BTreeMap<String, EndpointSlice>,
    syncing: bool,
    /// Last list handed out, so an unchanged list is not published again.
    current: Option<Endpoints>,
}

impl EndpointState {
    /// Applies one watch event. Returns the new endpoints when they changed.
    ///
    /// During a (re)list nothing is published until the list is complete, so a
    /// relist never shrinks the backends to the slices seen so far. A completed
    /// relist replaces everything, which drops slices deleted while the watch
    /// was disconnected.
    pub fn apply(
        &mut self,
        event: Event<EndpointSlice>,
        port: &ServicePort,
    ) -> Option<Endpoints> {
        match event {
            Event::Init => {
                self.syncing = true;
                self.initial.clear();
            }
            Event::InitApply(slice) => {
                self.initial.insert(slice.name_any(), slice);
            }
            Event::InitDone => {
                self.syncing = false;
                self.slices = std::mem::take(&mut self.initial);
            }
            Event::Apply(slice) => {
                self.slices.insert(slice.name_any(), slice);
            }
            Event::Delete(slice) => {
                self.slices.remove(&slice.name_any());
            }
        }
        if self.syncing {
            return None;
        }

        let endpoints = ready_endpoints(self.slices.values(), port);
        if self.current.as_ref() == Some(&endpoints) {
            return None;
        }
        self.current = Some(endpoints.clone());
        Some(endpoints)
    }
}

/// Ready endpoint addresses of `slices` on `port`, sorted and without duplicates.
#[cfg(test)]
fn ready_backends<'a>(
    slices: impl IntoIterator<Item = &'a EndpointSlice>,
    port: &ServicePort,
) -> Vec<SocketAddr> {
    ready_endpoints(slices, port).backends
}

/// Ready endpoints of `slices` on `port`.
///
/// Follows the EndpointSlice rules: an endpoint whose `ready` condition is unset
/// counts as ready, and slices that do not expose the requested port are skipped.
pub fn ready_endpoints<'a>(
    slices: impl IntoIterator<Item = &'a EndpointSlice>,
    port: &ServicePort,
) -> Endpoints {
    let mut backends = BTreeSet::new();
    let mut pods: BTreeMap<String, SocketAddr> = BTreeMap::new();

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
            let pod = endpoint
                .target_ref
                .as_ref()
                .filter(|target| target.kind.as_deref() == Some("Pod"))
                .and_then(|target| target.name.as_deref());
            for address in &endpoint.addresses {
                if let Ok(ip) = address.parse::<IpAddr>() {
                    let addr = SocketAddr::new(ip, port);
                    backends.insert(addr);
                    if let Some(pod) = pod {
                        pods.entry(pod.to_owned())
                            .and_modify(|lowest| *lowest = (*lowest).min(addr))
                            .or_insert(addr);
                    }
                }
            }
        }
    }

    Endpoints {
        backends: backends.into_iter().collect(),
        pods,
    }
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

    impl EndpointState {
        /// `apply`, keeping only the backend list.
        fn apply_backends(
            &mut self,
            event: Event<EndpointSlice>,
            port: &ServicePort,
        ) -> Option<Vec<SocketAddr>> {
            self.apply(event, port).map(|endpoints| endpoints.backends)
        }
    }

    fn named(name: &str, addresses: &[&str]) -> EndpointSlice {
        let mut slice = slice(
            "IPv4",
            &[("http", 80)],
            addresses.iter().map(|a| endpoint(a, Some(true))).collect(),
        );
        slice.metadata.name = Some(name.into());
        slice
    }

    fn http() -> ServicePort {
        ServicePort::Name("http".into())
    }

    #[test]
    fn publishes_the_initial_list_only_once_it_is_complete() {
        let mut state = EndpointState::default();

        assert_eq!(state.apply_backends(Event::Init, &http()), None);
        assert_eq!(
            state.apply_backends(Event::InitApply(named("a", &["10.0.0.1"])), &http()),
            None
        );
        assert_eq!(
            state.apply_backends(Event::InitApply(named("b", &["10.0.0.2"])), &http()),
            None
        );
        assert_eq!(
            state.apply_backends(Event::InitDone, &http()),
            Some(addrs(&["10.0.0.1:80", "10.0.0.2:80"]))
        );
    }

    #[test]
    fn an_empty_service_publishes_an_empty_list() {
        let mut state = EndpointState::default();
        state.apply_backends(Event::Init, &http());
        assert_eq!(state.apply_backends(Event::InitDone, &http()), Some(vec![]));
    }

    #[test]
    fn follows_changes_and_skips_ones_that_change_nothing() {
        let mut state = EndpointState::default();
        state.apply_backends(Event::Init, &http());
        state.apply_backends(Event::InitApply(named("a", &["10.0.0.1"])), &http());
        state.apply_backends(Event::InitDone, &http());

        // A new slice adds its endpoints.
        assert_eq!(
            state.apply_backends(Event::Apply(named("b", &["10.0.0.2"])), &http()),
            Some(addrs(&["10.0.0.1:80", "10.0.0.2:80"]))
        );
        // Same endpoints again (a label change, say): nothing to publish.
        assert_eq!(
            state.apply_backends(Event::Apply(named("b", &["10.0.0.2"])), &http()),
            None
        );
        // A pod becoming unready leaves the list.
        let mut unready = named("b", &[]);
        unready.endpoints = Some(vec![endpoint("10.0.0.2", Some(false))]);
        assert_eq!(
            state.apply_backends(Event::Apply(unready), &http()),
            Some(addrs(&["10.0.0.1:80"]))
        );
        // Deleting a slice removes its endpoints.
        assert_eq!(
            state.apply_backends(Event::Delete(named("a", &["10.0.0.1"])), &http()),
            Some(vec![])
        );
    }

    #[test]
    fn a_relist_keeps_the_old_list_until_done_then_drops_stale_slices() {
        let mut state = EndpointState::default();
        state.apply_backends(Event::Init, &http());
        state.apply_backends(Event::InitApply(named("a", &["10.0.0.1"])), &http());
        state.apply_backends(Event::InitApply(named("b", &["10.0.0.2"])), &http());
        state.apply_backends(Event::InitDone, &http());

        // The watch reconnects; slice "a" was deleted while it was down.
        assert_eq!(state.apply_backends(Event::Init, &http()), None);
        assert_eq!(
            state.apply_backends(Event::InitApply(named("b", &["10.0.0.2"])), &http()),
            None
        );
        assert_eq!(
            state.apply_backends(Event::InitDone, &http()),
            Some(addrs(&["10.0.0.2:80"]))
        );
    }

    #[test]
    fn a_relist_with_no_change_publishes_nothing() {
        let mut state = EndpointState::default();
        for _ in 0..2 {
            state.apply_backends(Event::Init, &http());
            state.apply_backends(Event::InitApply(named("a", &["10.0.0.1"])), &http());
            state.apply_backends(Event::InitDone, &http());
        }
        state.apply_backends(Event::Init, &http());
        state.apply_backends(Event::InitApply(named("a", &["10.0.0.1"])), &http());
        assert_eq!(state.apply_backends(Event::InitDone, &http()), None);
    }

    fn pod_endpoint(address: &str, pod: &str, ready: bool) -> Endpoint {
        Endpoint {
            target_ref: Some(k8s_openapi::api::core::v1::ObjectReference {
                kind: Some("Pod".into()),
                name: Some(pod.into()),
                ..Default::default()
            }),
            ..endpoint(address, Some(ready))
        }
    }

    #[test]
    fn maps_ready_pods_to_their_address() {
        let slices = [
            slice(
                "IPv4",
                &[("rtc", 5000)],
                vec![
                    pod_endpoint("10.0.0.1", "nes-session-a1b2c", true),
                    pod_endpoint("10.0.0.2", "nes-session-starting", false),
                    endpoint("10.0.0.3", Some(true)),
                ],
            ),
            slice(
                "IPv6",
                &[("rtc", 5000)],
                vec![pod_endpoint("fd00::1", "nes-session-a1b2c", true)],
            ),
        ];

        let endpoints = ready_endpoints(&slices, &ServicePort::Name("rtc".into()));

        assert_eq!(
            endpoints.backends,
            addrs(&["10.0.0.1:5000", "10.0.0.3:5000", "[fd00::1]:5000"])
        );
        // Not-ready pods and endpoints without a pod are left out; a
        // dual-stack pod keeps its IPv4 address.
        assert_eq!(
            endpoints.pods.into_iter().collect::<Vec<_>>(),
            vec![("nes-session-a1b2c".to_owned(), "10.0.0.1:5000".parse().unwrap())]
        );
    }

    #[test]
    fn no_slices_means_no_backends() {
        assert!(ready_backends(&[], &ServicePort::Number(80)).is_empty());
    }
}
