//! Treasury & owner management — a Rust port of the Motoko `Payments.mo` module.
//!
//! Provides owner-gated treasury functions for ICRC-1/ICRC-2 tokens: reading
//! the canister's token balance and withdrawing funds to a destination account.
//! Only the canister owner may withdraw.

use candid::{CandidType, Deserialize, Nat, Principal};
use ic_cdk::api::call::call;
use std::cell::RefCell;

/// An ICRC-1 account (owner + optional subaccount).
#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<Vec<u8>>,
}

/// ICRC-1 transfer arguments.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct TransferArg {
    pub from_subaccount: Option<Vec<u8>>,
    pub to: Account,
    pub amount: Nat,
    pub fee: Option<Nat>,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}

/// ICRC-1 transfer error (subset of the ledger's variant).
#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum TransferError {
    BadFee { expected_fee: Nat },
    BadBurn { min_burn_amount: Nat },
    InsufficientFunds { balance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

/// Errors returned by treasury operations.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum TreasuryError {
    /// The caller is not the canister owner.
    NotOwner,
    /// The ledger rejected the transfer.
    TransferFailed(String),
    /// The ledger canister itself trapped.
    LedgerTrap(String),
}

thread_local! {
    static OWNER: RefCell<Option<Principal>> = RefCell::new(None);
}

/// Initialize the treasury module, recording the canister owner.
pub fn init(owner: Principal) {
    OWNER.with_borrow_mut(|o| *o = Some(owner));
}

/// Read the current canister owner.
pub fn get_owner() -> Option<Principal> {
    OWNER.with_borrow(|o| *o)
}

/// Update the canister owner. Only the current owner may call this.
pub fn set_owner(caller: Principal, new_owner: Principal) -> Result<(), TreasuryError> {
    OWNER.with_borrow_mut(|o| match *o {
        Some(current) if current == caller => {
            *o = Some(new_owner);
            Ok(())
        }
        _ => Err(TreasuryError::NotOwner),
    })
}

/// Get this canister's balance of an ICRC-1 token on `ledger_id`.
///
/// Returns 0 if the ledger traps or doesn't exist.
pub async fn get_treasury_balance(self_id: Principal, ledger_id: Principal) -> Nat {
    let account = Account {
        owner: self_id,
        subaccount: None,
    };
    match call::<(Account,), (Nat,)>(ledger_id, "icrc1_balance_of", (account,)).await {
        Ok((balance,)) => balance,
        Err(_) => Nat::from(0u32),
    }
}

/// Withdraw `amount` of an ICRC-1 token to `destination`.
///
/// Only the current owner may call. Returns the block index on success.
pub async fn withdraw(
    caller: Principal,
    ledger_id: Principal,
    amount: Nat,
    destination: Account,
) -> Result<Nat, TreasuryError> {
    // SECURITY: the most important check — only the owner can withdraw.
    let owner = get_owner().ok_or(TreasuryError::NotOwner)?;
    if caller != owner {
        return Err(TreasuryError::NotOwner);
    }

    let args = TransferArg {
        from_subaccount: None,
        to: destination,
        amount,
        fee: None,
        memo: None,
        created_at_time: None,
    };

    match call::<(TransferArg,), (Result<Nat, TransferError>,)>(
        ledger_id,
        "icrc1_transfer",
        (args,),
    )
    .await
    {
        Ok((Ok(block_index),)) => Ok(block_index),
        Ok((Err(e),)) => Err(TreasuryError::TransferFailed(format!("{e:?}"))),
        Err(e) => Err(TreasuryError::LedgerTrap(format!("{e:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(n: u8) -> Principal {
        Principal::from_slice(&[n; 29])
    }

    #[test]
    fn set_owner_enforces_current_owner() {
        let owner = principal(1);
        let other = principal(2);
        let new = principal(3);
        init(owner);

        // Non-owner cannot change owner.
        assert!(matches!(set_owner(other, new), Err(TreasuryError::NotOwner)));
        assert_eq!(get_owner(), Some(owner));

        // Owner can change owner.
        assert!(set_owner(owner, new).is_ok());
        assert_eq!(get_owner(), Some(new));
    }

    #[test]
    fn withdraw_rejects_non_owner() {
        let owner = principal(4);
        let other = principal(5);
        init(owner);

        let dest = Account {
            owner: principal(9),
            subaccount: None,
        };
        // Non-owner withdraw is rejected before any inter-canister call.
        let rt = tokio_test::block_on(async {
            withdraw(other, principal(8), Nat::from(10u32), dest).await
        });
        assert!(matches!(rt, Err(TreasuryError::NotOwner)));
    }
}
