use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};

use crate::error::ContractError;
use crate::msg::{CountResponse, ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{State, STATE};

use umbral_pre::{Capsule, CapsuleFrag, PublicKey, DeserializableFromArray};

// Note, you can use StdResult in some functions where you do not
// make use of the custom errors
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let state = State {
        count: msg.count,
        owner: info.sender,
    };
    STATE.save(deps.storage, &state)?;

    Ok(Response::default())
}

// And declare a custom Error variant for the ones where you will want to make use of it
#[entry_point]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Increment {} => try_increment(deps),
        ExecuteMsg::Reset { count } => try_reset(deps, info, count),
        ExecuteMsg::VerifyCfrag { cfrag, capsule, verifying_pk, delegating_pk, receiving_pk}
            => try_verify_cfrag(deps,
                                cfrag,
                                capsule,
                                verifying_pk,
                                delegating_pk,
                                receiving_pk),
    }
}

pub fn try_increment(deps: DepsMut) -> Result<Response, ContractError> {
    STATE.update(deps.storage, |mut state| -> Result<_, ContractError> {
        state.count += 1;
        Ok(state)
    })?;

    Ok(Response::default())
}


pub fn try_verify_cfrag(_deps: DepsMut,
                        cfrag: String,
                        capsule: String,
                        verifying_pk: String,
                        delegating_pk: String,
                        receiving_pk: String) -> Result<Response, ContractError> {
    let cfrag_vec = base64::decode(&cfrag).unwrap();
    let cfrag = CapsuleFrag::from_bytes(&cfrag_vec).unwrap();

    let capsule_vec = base64::decode(&capsule).unwrap();
    let capsule = Capsule::from_bytes(&capsule_vec).unwrap();

    let verifying_pk_vec = base64::decode(&verifying_pk).unwrap();
    let verifying_pk = PublicKey::from_bytes(&verifying_pk_vec).unwrap();

    let delegating_pk_vec = base64::decode(&delegating_pk).unwrap();
    let delegating_pk = PublicKey::from_bytes(&delegating_pk_vec).unwrap();

    let receiving_pk_vec = base64::decode(&receiving_pk).unwrap();
    let receiving_pk = PublicKey::from_bytes(&receiving_pk_vec).unwrap();

    cfrag.verify(&capsule, &verifying_pk, &delegating_pk, &receiving_pk).unwrap();

    Ok(Response::default())
}


pub fn try_reset(deps: DepsMut, info: MessageInfo, count: i32) -> Result<Response, ContractError> {
    STATE.update(deps.storage, |mut state| -> Result<_, ContractError> {
        if info.sender != state.owner {
            return Err(ContractError::Unauthorized {});
        }
        state.count = count;
        Ok(state)
    })?;
    Ok(Response::default())
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetCount {} => to_binary(&query_count(deps)?),
    }
}

fn query_count(deps: Deps) -> StdResult<CountResponse> {
    let state = STATE.load(deps.storage)?;
    Ok(CountResponse { count: state.count })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, from_binary};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies(&[]);

        let msg = InstantiateMsg { count: 17 };
        let info = mock_info("creator", &coins(1000, "earth"));

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: CountResponse = from_binary(&res).unwrap();
        assert_eq!(17, value.count);
    }

    #[test]
    fn increment() {
        let mut deps = mock_dependencies(&coins(2, "token"));

        let msg = InstantiateMsg { count: 17 };
        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // beneficiary can release it
        let info = mock_info("anyone", &coins(2, "token"));
        let msg = ExecuteMsg::Increment {};
        let _res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        // should increase counter by 1
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: CountResponse = from_binary(&res).unwrap();
        assert_eq!(18, value.count);
    }

    #[test]
    fn reset() {
        let mut deps = mock_dependencies(&coins(2, "token"));

        let msg = InstantiateMsg { count: 17 };
        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // beneficiary can release it
        let unauth_info = mock_info("anyone", &coins(2, "token"));
        let msg = ExecuteMsg::Reset { count: 5 };
        let res = execute(deps.as_mut(), mock_env(), unauth_info, msg);
        match res {
            Err(ContractError::Unauthorized {}) => {}
            _ => panic!("Must return unauthorized error"),
        }

        // only the original creator can reset the counter
        let auth_info = mock_info("creator", &coins(2, "token"));
        let msg = ExecuteMsg::Reset { count: 5 };
        let _res = execute(deps.as_mut(), mock_env(), auth_info, msg).unwrap();

        // should now be 5
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: CountResponse = from_binary(&res).unwrap();
        assert_eq!(5, value.count);
    }

    #[test]
    fn verify() {
        let mut deps = mock_dependencies(&coins(2, "token"));

        let msg = InstantiateMsg { count: 17 };
        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // beneficiary can release it
        let info = mock_info("anyone", &coins(2, "token"));
        /*
        let cfrag =
            vec![2, 93, 74, 124, 175, 222, 1, 221, 165, 219, 39, 15, 156, 40, 128, 43, 100, 119, 234, 109, 41, 104, 108, 178, 81, 15, 132, 0, 1, 228, 127, 234, 227, 3, 128, 179, 6, 146, 56, 152, 168, 216, 201, 162, 249, 86, 127, 51, 194, 61, 17, 120, 153, 97, 51, 44, 221, 237, 209, 82, 156, 59, 15, 199, 202, 15, 175, 214, 238, 130, 106, 202, 87, 210, 9, 51, 172, 254, 72, 35, 161, 243, 229, 169, 70, 159, 217, 251, 217, 32, 228, 29, 95, 239, 236, 5, 218, 38, 2, 190, 219, 135, 235, 166, 19, 104, 26, 11, 93, 232, 102, 183, 51, 248, 195, 153, 109, 202, 130, 110, 64, 205, 119, 204, 48, 96, 180, 241, 186, 14, 112, 3, 181, 195, 253, 12, 184, 34, 17, 70, 3, 99, 143, 143, 113, 70, 195, 37, 67, 211, 241, 238, 147, 177, 9, 134, 76, 207, 248, 201, 211, 61, 194, 6, 3, 182, 215, 17, 189, 162, 162, 245, 73, 161, 26, 188, 241, 24, 252, 0, 80, 100, 44, 215, 46, 114, 15, 1, 122, 118, 120, 211, 69, 95, 136, 252, 59, 2, 148, 3, 166, 15, 141, 176, 1, 39, 122, 75, 50, 183, 87, 7, 205, 83, 9, 220, 207, 115, 252, 103, 17, 137, 72, 1, 16, 126, 183, 155, 148, 76, 2, 56, 251, 228, 42, 124, 210, 138, 135, 237, 81, 171, 48, 229, 127, 249, 61, 220, 155, 245, 4, 231, 155, 5, 137, 13, 113, 168, 101, 193, 164, 84, 40, 208, 242, 201, 42, 211, 48, 47, 47, 81, 44, 24, 211, 154, 200, 50, 252, 8, 64, 188, 42, 98, 2, 133, 40, 161, 119, 112, 138, 195, 93, 29, 101, 90, 118, 213, 192, 254, 69, 115, 14, 162, 91, 191, 236, 187, 200, 237, 2, 41, 18, 150, 132, 234, 58, 183, 181, 251, 18, 117, 145, 123, 146, 33, 2, 25, 194, 56, 12, 140, 225, 17, 192, 26, 29, 148, 129, 112, 34, 123, 96, 156, 33, 224, 249, 203, 78, 225, 50, 47, 51, 113, 159, 242, 37, 92, 223];
        let capsule =
            vec![3, 26, 77, 137, 91, 195, 79, 136, 71, 254, 62, 223, 112, 158, 47, 253, 59, 136, 177, 139, 193, 237, 144, 145, 224, 21, 161, 126, 209, 181, 222, 93, 134, 3, 140, 84, 67, 12, 212, 61, 27, 43, 77, 93, 185, 196, 11, 143, 251, 171, 178, 128, 114, 109, 171, 241, 109, 195, 159, 212, 247, 92, 13, 34, 72, 204, 120, 249, 251, 150, 5, 161, 67, 202, 84, 91, 134, 205, 93, 245, 47, 15, 204, 120, 72, 112, 95, 80, 94, 87, 219, 19, 21, 209, 10, 91, 162, 151];
        let verifying_pk = vec![3, 246, 132, 147, 125, 146, 229, 250, 111, 129, 255, 125, 33, 21, 103, 8, 123, 234, 205, 192, 144, 126, 124, 4, 168, 19, 233, 254, 136, 99, 54, 104, 93];
        let delegating_pk =vec![2, 58, 100, 133, 50, 79, 89, 225, 177, 191, 59, 243, 32, 214, 135, 185, 232, 255, 122, 187, 47, 4, 90, 158, 225, 120, 10, 97, 171, 18, 121, 142, 166];
        let receiving_pk = vec![2, 147, 66, 41, 41, 62, 115, 171, 113, 47, 159, 50, 124, 169, 238, 73, 37, 255, 165, 163, 157, 246, 144, 8, 103, 107, 187, 115, 86, 219, 19, 25, 148];
         */

        let cfrag = String::from(
            "Al1KfK/eAd2l2ycPnCiAK2R36m0paGyyUQ+EAAHkf+rjA4CzBpI4mKjYyaL5Vn8zwj0ReJlhMyzd7dFSnDsPx8oPr9bugmrKV9IJM6z+SCOh8+WpRp/Z+9kg5B1f7+wF2iYCvtuH66YTaBoLXehmtzP4w5ltyoJuQM13zDBgtPG6DnADtcP9DLgiEUYDY4+PcUbDJUPT8e6TsQmGTM/4ydM9wgYDttcRvaKi9UmhGrzxGPwAUGQs1y5yDwF6dnjTRV+I/DsClAOmD42wASd6SzK3VwfNUwncz3P8ZxGJSAEQfreblEwCOPvkKnzSioftUasw5X/5Pdyb9QTnmwWJDXGoZcGkVCjQ8skq0zAvL1EsGNOayDL8CEC8KmIChSihd3CKw10dZVp21cD+RXMOolu/7LvI7QIpEpaE6jq3tfsSdZF7kiECGcI4DIzhEcAaHZSBcCJ7YJwh4PnLTuEyLzNxn/IlXN8="
        );
        let capsule = String::from(
            "AxpNiVvDT4hH/j7fcJ4v/TuIsYvB7ZCR4BWhftG13l2GA4xUQwzUPRsrTV25xAuP+6uygHJtq/Ftw5/U91wNIkjMePn7lgWhQ8pUW4bNXfUvD8x4SHBfUF5X2xMV0Qpbopc="
        );
        let verifying_pk = String::from(
            "A/aEk32S5fpvgf99IRVnCHvqzcCQfnwEqBPp/ohjNmhd"
        );
        let delegating_pk = String::from(
            "AjpkhTJPWeGxvzvzINaHuej/ersvBFqe4XgKYasSeY6m"
        );
        let receiving_pk = String::from(
            "ApNCKSk+c6txL58yfKnuSSX/paOd9pAIZ2u7c1bbExmU"
        );

        // should have no error
        let msg = ExecuteMsg::VerifyCfrag { cfrag, capsule, verifying_pk, delegating_pk, receiving_pk };
        let _res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
    }

}
