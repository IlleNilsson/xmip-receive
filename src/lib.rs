#![forbid(unsafe_code)]

//! Receive Ports, Receive Locations, and what arrives at them.

use authenticate::{Acceptance, Presented};
use context::{Alignment, OnMisalignment};
use stream::Stream;
use xcore::{Arriving, ArtifactId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveLocationType {
    Composite,
    DataTransfer,
    BatchLoad,
}

/// What a Receive Location does when the two identity layers disagree.
///
/// ADR-0019 clause 7. `none` and `accept` are the defaults because a default of
/// `strict` would refuse every relayed integration on the first day, and the
/// failure would present as a routing bug rather than a policy decision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdentityPolicy {
    pub alignment: Alignment,
    pub on_misalignment: OnMisalignment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveLocation {
    pub artifact_id: ArtifactId,
    pub name: String,
    pub uri: String,
    pub transport: String,
    pub location_type: ReceiveLocationType,

    /// The closed set of identities and mechanisms this location takes.
    ///
    /// ADR-0019 clause 1. Left as [`Acceptance::closed`], the location accepts
    /// nothing — an unconfigured endpoint is closed, not open.
    pub accept: Acceptance,

    pub identity_policy: IdentityPolicy,
}

impl ReceiveLocation {
    #[must_use]
    pub fn new(
        artifact_id: ArtifactId,
        name: impl Into<String>,
        uri: impl Into<String>,
        transport: impl Into<String>,
        location_type: ReceiveLocationType,
    ) -> Self {
        Self {
            artifact_id,
            name: name.into(),
            uri: uri.into(),
            transport: transport.into(),
            location_type,
            accept: Acceptance::closed(),
            identity_policy: IdentityPolicy::default(),
        }
    }

    #[must_use]
    pub fn accepting(mut self, accept: Acceptance) -> Self {
        self.accept = accept;
        self
    }

    #[must_use]
    pub const fn aligning(mut self, policy: IdentityPolicy) -> Self {
        self.identity_policy = policy;
        self
    }

    /// Whether this location can take anything at all.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.accept.is_closed()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivePort {
    pub artifact_id: ArtifactId,
    pub name: String,
    pub version: String,
}

/// Bytes off a transport, and the credential the transport observed.
///
/// **Nothing here is authenticated.** The transport extracts what it can see —
/// a client certificate, an `Authorization` header, the path and permissions of
/// a drop folder — and the gate runs afterwards. This previously carried a
/// resolved `PartyId`, which presumed the answer to a question that had not yet
/// been asked.
#[derive(Clone, Debug)]
pub struct ReceivedStream {
    pub stream: Stream,

    /// How it got here: pushed, detected or scheduled.
    ///
    /// Set by the transport, which is the only thing that knows. A Receive
    /// Location watching a folder produces [`Arriving::Detected`]; the same
    /// folder polled on a timer produces [`Arriving::Scheduled`]; an HTTP
    /// endpoint produces [`Arriving::Pushed`]. Defaults to pushed because that
    /// is the case with a caller to answer to.
    pub arriving: Arriving,

    pub source_uri: String,
    /// What the transport observed. `None` only where the technology offers
    /// nothing at all to observe.
    pub presented: Option<Presented>,
    pub transport_properties: Vec<(String, String)>,
}

impl ReceivedStream {
    #[must_use]
    pub fn new(stream: Stream, source_uri: impl Into<String>) -> Self {
        Self {
            stream,
            arriving: Arriving::Pushed,
            source_uri: source_uri.into(),
            presented: None,
            transport_properties: Vec::new(),
        }
    }

    /// Xmip was watching and it appeared. Nobody connected.
    #[must_use]
    pub const fn detected(mut self) -> Self {
        self.arriving = Arriving::Detected;
        self
    }

    /// A timer fired and Xmip went and fetched it. Xmip is the client, so any
    /// credential in play is Xmip's own and proves nothing about the source.
    #[must_use]
    pub const fn scheduled(mut self) -> Self {
        self.arriving = Arriving::Scheduled;
        self
    }

    #[must_use]
    pub fn presenting(mut self, presented: Presented) -> Self {
        self.presented = Some(presented);
        self
    }

    #[must_use]
    pub fn with_property(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.transport_properties.push((name.into(), value.into()));
        self
    }
}

xcore::declare_error!(ReceiveError);

pub trait ReceiveTransport: Send + Sync {
    fn technology(&self) -> &'static str;
    fn receive(&self, location: &ReceiveLocation) -> Result<Option<ReceivedStream>, ReceiveError>;
}

pub trait ReceivePublisher: Send + Sync {
    fn publish(
        &self,
        port: &ReceivePort,
        location: &ReceiveLocation,
        received: ReceivedStream,
    ) -> Result<(), ReceiveError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use xcore::mechanism;

    fn location() -> ReceiveLocation {
        ReceiveLocation::new(
            ArtifactId::new(1),
            "partner-x",
            "https://xmip.example/in/partner-x",
            "https",
            ReceiveLocationType::DataTransfer,
        )
    }

    #[test]
    fn an_unconfigured_location_takes_nothing() {
        assert!(!location().is_open());
    }

    #[test]
    fn a_location_declares_a_closed_set() {
        let configured = location().accepting(
            Acceptance::closed()
                .accepting(&mechanism::mutual_tls())
                .accepting(&mechanism::oauth2()),
        );

        assert!(configured.is_open());
        assert!(configured.accept.declares(&mechanism::mutual_tls()));
        assert!(!configured.accept.declares(&mechanism::api_key()));
    }

    #[test]
    fn the_default_policy_never_compares_the_two_layers() {
        // The relaying case. One authenticated connection carrying traffic for
        // many Parties is ordinary, not a fault.
        let policy = location().identity_policy;

        assert_eq!(policy.alignment, Alignment::None);
        assert_eq!(policy.on_misalignment, OnMisalignment::Accept);
    }

    #[test]
    fn what_arrives_is_not_yet_authenticated() {
        use xcore::StreamId;

        let received = ReceivedStream::new(
            Stream::new(StreamId::new(1), b"<order/>".to_vec(), None),
            "https://xmip.example/in/partner-x",
        )
        .presenting(Presented::passed(
            mechanism::mutual_tls(),
            "CN=partner-x.example",
        ));

        // A credential was observed. Whether it holds is the gate's question,
        // and there is nowhere here to record an answer to it.
        assert!(received.presented.is_some());
    }

    #[test]
    fn a_technology_with_nothing_to_observe_presents_nothing() {
        use xcore::StreamId;

        // Modbus, CAN bus, a raw TCP socket. The circumstance becomes the
        // identity later; the transport itself saw no credential.
        let received = ReceivedStream::new(
            Stream::new(StreamId::new(2), b"\x01\x02".to_vec(), None),
            "tcp://10.0.0.4:502",
        );

        assert!(received.presented.is_none());
    }
}
