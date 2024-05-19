use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Decimal, Uint256};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub enum Token {
    Native { denom: String },
    Token { address: String },
}

#[cw_serde]
pub struct State {
    pub admin: Addr,
    pub raising_token: Token,
    pub offering_token: Token,
    pub start_time: u64,
    pub end_time: u64,
    pub raising_amount: Uint256,
    pub offering_amount: Uint256,
    pub total_amount: Uint256,
    pub allow_claim: bool,
}

#[cw_serde]
#[derive(Default)]
pub struct User {
    pub amount: Uint256,
    pub claimed: bool,
}

pub const STATE_KEY: &str = "state";
pub const STATE: Item<State> = Item::new(STATE_KEY);
pub const USER_INFO: Map<String, User> = Map::new("user_info");
