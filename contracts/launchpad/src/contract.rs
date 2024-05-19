use std::{
    ops::{Div, Mul},
    str::FromStr,
};

use cosmwasm_std::{
    attr, coins, entry_point, from_json, to_json_binary, Addr, BankMsg, Binary, CosmosMsg, Decimal,
    Decimal256, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Uint128, Uint256,
    WasmMsg,
};
use cw20::{BalanceResponse, Cw20ExecuteMsg};
use cw20_base::ContractError;

use crate::{
    msg::{
        ConfigResponse, Cw20HookMsg, Cw20ReceiveMsg, ExecuteMsg, InstantiateMsg,
        IsClaimingAllowedResponse, MigrateMsg, QueryMsg, TotalAmountResponse, UserInfoResponse,
    },
    state::{State, Token, User, STATE, USER_INFO},
};

// version info for migration info
// const CONTRACT_NAME: &str = "crates.io:launchpad";
// const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let state = State {
        admin: msg.admin,
        raising_token: msg.raising_token,
        offering_token: msg.offering_token,
        start_time: msg.start_time,
        end_time: msg.end_time,
        raising_amount: msg.raising_amount,
        offering_amount: msg.offering_amount,
        total_amount: Uint256::zero(),
        allow_claim: false,
    };
    STATE.save(deps.storage, &state)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, StdError> {
    match msg {
        ExecuteMsg::Receive(msg) => receive_cw20(deps, env, info, msg),
        ExecuteMsg::Deposit {} => {
            let token = Token::Native {
                denom: "inj".to_string(),
            };
            let funds = info.funds.get(0).unwrap();
            if funds.denom != "inj" {
                return Err(StdError::generic_err("Wrong denom"));
            }

            deposit(
                deps,
                env,
                info.clone(),
                info.sender.clone(),
                token,
                funds.amount.into(),
            )
        }
        ExecuteMsg::Harvest {} => harvest(deps, env, info),
        ExecuteMsg::UpdateConfig {
            raising_token,
            offering_token,
            start_time,
            end_time,
            raising_amount,
            offering_amount,
        } => update_config(
            deps,
            env,
            info,
            raising_token,
            offering_token,
            start_time,
            end_time,
            raising_amount,
            offering_amount,
        ),
        ExecuteMsg::FinalWithdraw {
            raise_amount,
            offer_amount,
        } => final_withdraw(deps, env, info, raise_amount, offer_amount),
        ExecuteMsg::FlipAllowClaim {} => flip_allow_claim(deps, info),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    Ok(Response::default())
}

pub fn update_config(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    raising_token: Option<Token>,
    offering_token: Option<Token>,
    start_time: Option<u64>,
    end_time: Option<u64>,
    raising_amount: Option<Uint256>,
    offering_amount: Option<Uint256>,
) -> StdResult<Response> {
    let mut state = STATE.load(deps.storage)?;

    if state.admin != info.sender {
        return Err(StdError::generic_err("Unauthorized: not admin"));
    }

    if raising_token.is_some() {
        state.raising_token = raising_token.unwrap();
    }

    if offering_token.is_some() {
        state.offering_token = offering_token.unwrap();
    }

    if offering_amount.is_some() {
        state.offering_amount = offering_amount.unwrap();
    }

    if start_time.is_some() {
        state.start_time = start_time.unwrap();
    }

    if end_time.is_some() {
        state.end_time = end_time.unwrap();
    }

    if raising_amount.is_some() {
        state.raising_amount = raising_amount.unwrap();
    }

    STATE.save(deps.storage, &state)?;

    Ok(Response::new().add_attributes(vec![attr("action", "update_config")]))
}

pub fn receive_cw20(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    cw20_msg: Cw20ReceiveMsg,
) -> StdResult<Response> {
    let state = STATE.load(deps.storage)?;

    let (_token_type, token_identifier) = match state.raising_token.clone() {
        Token::Native { denom } => ("native", denom),
        Token::Token { address } => ("token", address),
    };

    match from_json(&cw20_msg.msg) {
        Ok(Cw20HookMsg::Deposit {}) => {
            // only whitelisted tokens can execute this message
            if info.sender.to_string() != token_identifier {
                return Err(StdError::generic_err("unauthorized"));
            }

            let cw20_sender = deps.api.addr_validate(&cw20_msg.sender)?;
            deposit(
                deps,
                env,
                info,
                cw20_sender,
                state.raising_token,
                cw20_msg.amount,
            )
        }
        Err(_) => Err(StdError::generic_err("data should be given")),
    }
}

fn deposit(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    user_address: Addr,
    token: Token,
    amount: Uint256,
) -> Result<Response, StdError> {
    let mut state = STATE.load(deps.storage)?;

    let (token_type, token_identifier) = match token.clone() {
        Token::Native { denom } => ("native", denom),
        Token::Token { address } => ("token", address),
    };

    // Check if it's within the launchpad time
    if env.block.time.seconds() < state.start_time || env.block.time.seconds() > state.end_time {
        return Err(StdError::generic_err("Not in launchpad time"));
    }

    // Ensure the deposit amount is greater than 0
    if amount.is_zero() {
        return Err(StdError::generic_err(
            "Deposit amount must be greater than 0",
        ));
    }

    if token_type == "native" {
        // Transfer tokens from sender to the contract
        if info.funds.len() != 1 || info.funds[0].denom != token_identifier {
            return Err(StdError::generic_err("Wrong denom"));
        }

        if info.funds[0].amount < Uint128::from_str(&amount.to_string())? {
            return Err(StdError::generic_err("Wrong deposit amount"));
        }
    }

    // Update user information
    let mut user = USER_INFO
        .may_load(deps.storage, user_address.to_string())?
        .unwrap_or_default();

    user.amount += amount;
    USER_INFO.save(deps.storage, user_address.to_string(), &user)?;

    // Update total amount
    state.total_amount += amount;
    STATE.save(deps.storage, &state)?;

    return Ok(Response::new().add_attributes(vec![
        attr("action", "deposit"),
        attr("address", user_address.to_string()),
        attr("amount", amount),
    ]));
}

fn harvest(deps: DepsMut, env: Env, info: MessageInfo) -> Result<Response, StdError> {
    let state = STATE.load(deps.storage)?;

    // Check if it's after the harvest time
    if env.block.time.seconds() <= state.end_time {
        return Err(StdError::generic_err("Not in harvest time"));
    }

    // Get user information
    let mut user = USER_INFO
        .may_load(deps.storage, info.sender.to_string())?
        .unwrap_or_default();

    // Check if the user has participated
    if user.amount.is_zero() {
        return Err(StdError::generic_err("User has not participated"));
    }

    // Check if the user has already claimed
    if user.claimed {
        return Err(StdError::generic_err("Already claimed"));
    }

    // Check if claiming is allowed
    if !state.allow_claim {
        return Err(StdError::generic_err("Claiming not allowed"));
    }

    // Calculate offering and refund amounts
    // 1e12 & 1e6
    // let user_allocation = get_user_allocation(deps.as_ref(), info.sender.to_string())?;
    let (offering_amount, refund_amount) = get_user_amount(deps.as_ref(), info.sender.to_string())?;
    // let offering_amount = get_offering_amount(
    //     user_allocation,
    //     user.amount,
    //     state.total_amount,
    //     state.raising_amount,
    //     state.offering_amount,
    // )?;
    // let refund_amount = get_refunding_amount(
    //     user_allocation,
    //     user.amount,
    //     state.total_amount,
    //     state.raising_amount,
    //     state.offering_amount,
    // )?;

    let mut messages: Vec<CosmosMsg> = vec![];
    // Transfer offering tokens
    if offering_amount > Uint256::from(0u128) {
        let transfer_msg = process_transfers(
            info.sender.to_string(),
            state.offering_token.clone(),
            offering_amount.clone(),
        )?;
        messages.push(transfer_msg);
    }

    // Transfer refund tokens
    if refund_amount > Uint256::from(0u128) {
        let transfer_msg = process_transfers(
            info.sender.to_string(),
            state.raising_token.clone(),
            refund_amount.clone(),
        )?;
        messages.push(transfer_msg);
    }

    // Update user information
    user.claimed = true;
    USER_INFO.save(deps.storage, info.sender.to_string(), &user)?;

    return Ok(Response::new().add_messages(messages).add_attributes(vec![
        attr("action", "harvest"),
        attr("address", info.sender.to_string()),
        attr("offering_amount", offering_amount),
        attr("refund_amount", refund_amount),
    ]));
}

pub fn final_withdraw(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    raise_amount: Uint256,
    offer_amount: Uint256,
) -> Result<Response, StdError> {
    let state = STATE.load(deps.storage)?;
    let raising_token = state.clone().raising_token.clone();

    let (token_type, token_identifier) = match raising_token.clone() {
        Token::Native { denom } => ("native", denom),
        Token::Token { address } => ("token", address),
    };

    // Check if the sender is the admin
    if info.sender.to_string() != state.admin {
        return Err(StdError::generic_err("Unauthorized: not admin"));
    }

    let msg = cw20::Cw20QueryMsg::Balance {
        address: env.contract.address.to_string(),
    };
    let balance_response: cw20::BalanceResponse = match state.offering_token.clone() {
        Token::Native { denom } => {
            let coin = deps
                .querier
                .query_balance(env.contract.address.to_string(), denom)?;
            BalanceResponse {
                balance: coin.amount,
            }
        }
        Token::Token { address } => deps.querier.query_wasm_smart(&address, &msg).unwrap(),
    };

    if token_type == "native" {
        let raising_balance = deps
            .querier
            .query_balance(env.contract.address.to_string(), token_identifier)?;
        // Check if the requested raise_amount is available
        if raise_amount > Uint256::from_uint128(raising_balance.amount) {
            return Err(StdError::generic_err("Not enough raising tokens"));
        }
    } else {
        let raising_balance: cw20::BalanceResponse = deps
            .querier
            .query_wasm_smart(&token_identifier, &msg)
            .unwrap();
        // Check if the requested raise_amount is available
        if raise_amount > Uint256::from_uint128(raising_balance.balance) {
            return Err(StdError::generic_err("Not enough raising tokens"));
        }
    }

    // Check if the requested offer_amount is available
    if offer_amount > Uint256::from_uint128(balance_response.balance) {
        return Err(StdError::generic_err("Not enough offering tokens"));
    }

    let mut messages: Vec<CosmosMsg> = vec![];
    // Transfer raising denom tokens to admin
    if raise_amount > Uint256::zero() {
        let transfer_msg = process_transfers(
            info.sender.to_string(),
            state.raising_token.clone(),
            raise_amount.clone(),
        )?;
        messages.push(transfer_msg);
    }

    // Transfer offering tokens to admin
    if offer_amount > Uint256::zero() {
        let msg = process_transfers(
            info.sender.to_string(),
            state.offering_token.clone(),
            offer_amount.clone(),
        )?;
        messages.push(msg);
    }

    return Ok(Response::new().add_messages(messages).add_attributes(vec![
        attr("action", "final_withdraw"),
        attr("offer_amount", offer_amount),
        attr("raise_amount", raise_amount),
    ]));
}

pub fn flip_allow_claim(deps: DepsMut, info: MessageInfo) -> Result<Response, StdError> {
    let mut state = STATE.load(deps.storage)?;

    if state.admin != info.sender {
        return Err(StdError::generic_err("Unauthorized: not admin"));
    }

    state.allow_claim = !state.allow_claim;
    STATE.save(deps.storage, &state)?;

    return Ok(Response::default());
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetUser { address } => to_json_binary(&query_user(deps, env, address)?),
        QueryMsg::GetUserAllocation { address } => {
            to_json_binary(&get_user_allocation(deps, address.to_string())?)
        }
        QueryMsg::GetUserAmount { address } => {
            to_json_binary(&get_user_amount(deps, address.to_string())?)
        }
        QueryMsg::GetTotalAmount {} => to_json_binary(&query_total_amount(deps)?),
        QueryMsg::Config {} => to_json_binary(&query_config(deps)?),
        QueryMsg::IsClaimingAllowed {} => to_json_binary(&query_is_claiming_allowed(deps)?),
    }
}

fn query_user(deps: Deps, _env: Env, address: Addr) -> StdResult<UserInfoResponse> {
    let user = USER_INFO
        .may_load(deps.storage, address.to_string())?
        .unwrap_or(User {
            amount: Uint256::zero(),
            claimed: false,
        });

    Ok(UserInfoResponse {
        address,
        amount: user.amount,
        claimed: user.claimed,
    })
}

fn query_total_amount(deps: Deps) -> StdResult<TotalAmountResponse> {
    let state = STATE.load(deps.storage)?;

    Ok(TotalAmountResponse {
        total_amount: state.total_amount,
    })
}

pub fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let state = STATE.load(deps.storage)?;

    Ok(ConfigResponse {
        admin: state.admin,
        raising_token: state.raising_token.clone(),
        offering_token: state.offering_token,
        start_time: state.start_time,
        end_time: state.end_time,
        raising_amount: state.raising_amount,
        offering_amount: state.offering_amount,
        total_amount: state.total_amount,
        allow_claim: state.allow_claim,
    })
}

fn query_is_claiming_allowed(deps: Deps) -> StdResult<IsClaimingAllowedResponse> {
    let state = STATE.load(deps.storage)?;

    Ok(IsClaimingAllowedResponse {
        is_claiming_allowed: state.allow_claim,
    })
}

fn get_user_allocation(deps: Deps, address: String) -> StdResult<Decimal256> {
    let state = STATE.load(deps.storage)?;
    let user = USER_INFO
        .may_load(deps.storage, address.to_string())?
        .unwrap_or_default();

    if user.amount.is_zero() {
        return Ok(Decimal256::zero());
    }

    // let user_allocation = user
    //     .amount
    //     .mul(Uint256::from_u128(1000000000000))
    //     .checked_div(state.total_amount)?
    //     .checked_div(Uint256::from_u128(1000000))?;

    let ratio = Decimal256::from_ratio(user.amount, state.total_amount);

    Ok(ratio)
}

fn get_user_amount(deps: Deps, address: String) -> StdResult<(Uint256, Uint256)> {
    let state = STATE.load(deps.storage)?;
    let user = USER_INFO
        .may_load(deps.storage, address.to_string())?
        .unwrap_or_default();

    if user.amount.is_zero() {
        return Ok((Uint256::zero(), Uint256::zero()));
    }

    // let user_allocation = user
    //     .amount
    //     .mul(Uint256::from_u128(1000000000000))
    //     .checked_div(state.total_amount)?
    //     .checked_div(Uint256::from_u128(1000000))?;
    let user_allocation = get_user_allocation(deps, address.clone())?;

    let offer = get_offering_amount(
        user_allocation,
        user.amount,
        state.total_amount,
        state.raising_amount,
        state.offering_amount,
    )?;
    let refund = get_refunding_amount(
        user_allocation,
        user.amount,
        state.total_amount,
        state.raising_amount,
        state.offering_amount,
    )?;

    Ok((offer, refund))
}

// Helper functions for calculating amounts
fn get_offering_amount(
    user_allocation: Decimal256,
    user_amount: Uint256,
    total_amount: Uint256,
    raising_amount: Uint256,
    offering_amount: Uint256,
) -> StdResult<Uint256> {
    // if (totalAmount > raisingAmount) {
    //     uint256 allocation = getUserAllocation(_user);
    //     return offeringAmount.mul(allocation).div(1e6);
    //   }
    //   else {
    //     // userInfo[_user] / (raisingAmount / offeringAmount)
    //     return userInfo[_user].amount.mul(offeringAmount).div(raisingAmount);
    //   }

    // userInfo[_user].amount.mul(offeringAmount).div(raisingAmount);
    if user_amount.is_zero() {
        return Ok(Uint256::zero());
    }

    if total_amount > raising_amount {
        return Ok(offering_amount.mul(user_allocation));
    } else {
        return Ok(user_amount
            .mul(offering_amount)
            .checked_div(raising_amount)?);
    }

    // if raising_amount > Uint256::zero() {
    //     let allocation = user_amount.multiply_ratio(Uint256::from_u128(1, 1), raising_amount);
    //     allocation.multiply_ratio(offering_amount, Uint256::from_u128(1, 1))
    // } else {
    //     user_amount.multiply_ratio(offering_amount, raising_amount)
    // }
}

fn get_refunding_amount(
    user_allocation: Decimal256,
    user_amount: Uint256,
    total_amount: Uint256,
    raising_amount: Uint256,
    _offering_amount: Uint256,
) -> StdResult<Uint256> {
    // if (totalAmount <= raisingAmount) {
    //     return 0;
    //   }
    //   uint256 allocation = getUserAllocation(_user);
    //   uint256 payAmount = raisingAmount.mul(allocation).div(1e6);
    //   return userInfo[_user].amount.sub(payAmount);
    if user_amount.is_zero() {
        return Ok(Uint256::zero());
    }

    if total_amount <= raising_amount {
        return Ok(Uint256::zero());
    }
    let pay_amount = raising_amount.mul(user_allocation);
    let result = user_amount.checked_sub(pay_amount)?;

    // if raising_amount > Uint256::zero() {
    //     let allocation = user_amount.multiply_ratio(Uint256::from_u128(1, 1), raising_amount);
    //     user_amount - allocation
    // } else {
    //     Uint256::zero()
    // }
    return Ok(result);
}

fn process_transfers(recipient: String, token: Token, amount: Uint256) -> StdResult<CosmosMsg> {
    match token {
        Token::Native { denom } => Ok(CosmosMsg::Bank(BankMsg::Send {
            to_address: recipient.to_string(),
            amount: coins(Uint128::from_str(&amount.to_string())?.u128(), denom),
        })),
        Token::Token { address } => Ok(CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: address.to_string(),
            msg: to_json_binary(&Cw20ExecuteMsg::Transfer {
                recipient: recipient.to_string(),
                amount: Uint128::from_str(&amount.to_string())?,
            })?,
            funds: vec![],
        })),
    }
}
