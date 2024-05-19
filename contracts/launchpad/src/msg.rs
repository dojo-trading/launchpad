use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, Decimal, Uint128, Uint256};

use crate::state::Token;

// use crate::state::{StakerInfo, StakerResponse, StakerListResponse};

#[cw_serde]
pub struct InstantiateMsg {
    pub admin: Addr,
    pub raising_token: Token,
    pub offering_token: Token,
    pub start_time: u64,
    pub end_time: u64,
    pub raising_amount: Uint256,
    pub offering_amount: Uint256,
}

#[cw_serde]
pub struct MigrateMsg {
    pub msg: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    Receive(Cw20ReceiveMsg),
    Deposit {},
    Harvest {},
    UpdateConfig {
        raising_token: Option<Token>,
        offering_token: Option<Token>,
        start_time: Option<u64>,
        end_time: Option<u64>,
        raising_amount: Option<Uint256>,
        offering_amount: Option<Uint256>,
    },
    FinalWithdraw {
        raise_amount: Uint256, // amount of raising token to withdraw
        offer_amount: Uint256, // amount of tokens that are being sold to withdraw
    },
    FlipAllowClaim {},
}

#[cw_serde]
pub enum Cw20HookMsg {
    Deposit {},
}

#[cw_serde]
pub struct Cw20ReceiveMsg {
    pub sender: String,
    pub amount: Uint256,
    pub msg: Binary,
}

// Define query structs for the responses
#[cw_serde]
pub struct UserInfoResponse {
    pub address: Addr,
    pub amount: Uint256,
    pub claimed: bool,
}

#[cw_serde]
pub struct TotalAmountResponse {
    pub total_amount: Uint256,
}

#[cw_serde]
pub struct ConfigResponse {
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
pub struct IsClaimingAllowedResponse {
    pub is_claiming_allowed: bool,
}

// Define the query message enum
#[cw_serde]
pub enum QueryMsg {
    GetUser { address: Addr },
    GetUserAllocation { address: Addr },
    GetUserAmount { address: Addr },
    GetTotalAmount {},
    Config {},
    IsClaimingAllowed {},
}

#[cw_serde]
pub struct StakerInfoResponse {
    pub staker: String,
    pub reward_index: Decimal,
    pub bond_amount: Uint128,
    pub pending_reward: Uint128,
}

#[cw_serde]
pub enum StakingQueryMsg {
    StakerInfo { staker: Addr, block_time: u64 },
    BalanceOf { address: Addr },
}
