pub mod channel;
pub mod committee;
pub mod committee_assets;
pub mod committee_health;
pub mod configs;
pub mod ethereum;
pub mod facility;
pub mod mining;
pub mod rpc;
pub mod system;
pub mod timestamp;

pub struct Query<'a> {
    pub(crate) client: &'a crate::NodeClient,
}

impl<'a> Query<'a> {
    pub fn channel(&self) -> channel::Channel<'a> {
        channel::Channel {
            client: self.client,
        }
    }

    pub fn committee(&self) -> committee::Committee<'a> {
        committee::Committee {
            client: self.client,
        }
    }

    pub fn committee_health(&self) -> committee_health::CommitteeHealth<'a> {
        committee_health::CommitteeHealth {
            client: self.client,
        }
    }

    pub fn configs(&self) -> configs::Configs<'a> {
        configs::Configs {
            client: self.client,
        }
    }

    pub fn ethereum(&self) -> ethereum::Ethereum<'a> {
        ethereum::Ethereum {
            client: self.client,
        }
    }

    pub fn facility(&self) -> facility::Facility<'a> {
        facility::Facility {
            client: self.client,
        }
    }

    pub fn mining(&self) -> mining::Mining<'a> {
        mining::Mining {
            client: self.client,
        }
    }

    pub fn rpc(&self) -> rpc::Rpc<'a> {
        rpc::Rpc {
            client: self.client,
        }
    }

    pub fn system(&self) -> system::System<'a> {
        system::System {
            client: self.client,
        }
    }

    pub fn timestamp(&self) -> timestamp::Timestamp<'a> {
        timestamp::Timestamp {
            client: self.client,
        }
    }

    pub fn committee_assets(&self) -> committee_assets::CommitteeAssets<'a> {
        committee_assets::CommitteeAssets {
            client: self.client,
        }
    }
}
