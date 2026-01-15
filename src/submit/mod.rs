pub mod channel;
pub mod committee;
pub mod committee_assets;
pub mod committee_health;
pub mod ethereum;
pub mod facility;
pub mod mining;
pub mod rpc;

pub struct Submit<'a> {
    pub(crate) client: &'a crate::NodeClient,
}

impl<'a> Submit<'a> {
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

    pub fn committee_assets(&self) -> committee_assets::CommitteeAssets<'a> {
        committee_assets::CommitteeAssets {
            client: self.client,
        }
    }
}
