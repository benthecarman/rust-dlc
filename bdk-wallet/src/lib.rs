//! # BDK

extern crate bdk;
extern crate bitcoin;
extern crate dlc_manager;
extern crate rust_bitcoin_coin_selection;

use bdk::database::BatchDatabase;
use bdk::wallet::AddressIndex;
use bdk::SignOptions;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::{Address, PrivateKey, Script, Transaction, TxIn, TxOut, Txid, Witness};

use dlc_manager::error::Error as ManagerError;
use dlc_manager::error::Error::WalletError;
use dlc_manager::{Signer, Utxo, Wallet};

#[derive(Debug)]
pub enum Error {
    MissingTransaction,
    GenericError,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::MissingTransaction => write!(f, "BDK Missing Transaction"),
            Error::GenericError => write!(f, "BDK Generic Error"),
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        "dlc-bdk error"
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}

pub struct BDKDLCWallet<D> {
    pub bdk_wallet: bdk::Wallet<D>,
    sk: SecretKey,
}

fn bdk_err_to_manager_err(e: bdk::Error) -> ManagerError {
    WalletError(Box::new(e))
}

impl From<Error> for ManagerError {
    fn from(e: Error) -> ManagerError {
        WalletError(Box::new(e))
    }
}

fn err_to_manager_err(e: Error) -> ManagerError {
    WalletError(Box::new(e))
}

impl<D> Signer for BDKDLCWallet<D>
where
    D: BatchDatabase,
{
    fn sign_tx_input(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        tx_out: &TxOut,
        redeem_script: Option<Script>,
    ) -> Result<(), ManagerError> {
        let sig_options = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };

        // need an unsigned version of the tx to sign
        let unsigned_tx = {
            let tx_clone = tx.clone();
            let unsigned_inputs = tx_clone
                .input
                .iter()
                .map(|i| TxIn {
                    previous_output: i.previous_output,
                    script_sig: Script::new(),
                    sequence: i.sequence,
                    witness: Witness::default(),
                })
                .collect();

            Transaction {
                version: tx_clone.version,
                lock_time: tx_clone.lock_time,
                input: unsigned_inputs,
                output: tx_clone.output,
            }
        };

        let psbt_r = PartiallySignedTransaction::from_unsigned_tx(unsigned_tx);

        match psbt_r {
            Ok(mut psbt) => {
                psbt.inputs[input_index].witness_utxo = Some(tx_out.clone());
                psbt.inputs[input_index].redeem_script = redeem_script;

                self.bdk_wallet
                    .sign(&mut psbt, sig_options)
                    .map_err(bdk_err_to_manager_err)?;

                let signed_tx = psbt.extract_tx();

                tx.input[input_index].script_sig = signed_tx.input[input_index].script_sig.clone();
                tx.input[input_index].witness = signed_tx.input[input_index].witness.clone();

                Ok(())
            }
            Err(e) => Err(WalletError(Box::new(e))),
        }
    }

    fn get_secret_key_for_pubkey(&self, pubkey: &PublicKey) -> Result<SecretKey, ManagerError> {
        let net = self.bdk_wallet.network();
        let priv_key = PrivateKey::new(self.sk, net);

        let my_pub_key = priv_key.public_key(&Secp256k1::new());

        if &my_pub_key.inner == pubkey {
            Ok(self.sk)
        } else {
            Err(ManagerError::InvalidState(
                "Received wrong public key".to_string(),
            ))
        }
    }
}

impl<D> Wallet for BDKDLCWallet<D>
where
    D: BatchDatabase,
{
    fn get_new_address(&self) -> Result<Address, ManagerError> {
        let addr = self.bdk_wallet.get_address(AddressIndex::New);
        match addr {
            Ok(address_info) => Ok(address_info.address),
            Err(bdk_err) => Err(bdk_err_to_manager_err(bdk_err)),
        }
    }

    fn get_new_secret_key(&self) -> Result<SecretKey, ManagerError> {
        Ok(self.sk)
    }

    // fixme doesn't use fee rate
    // fixme doesn't lock utxos
    fn get_utxos_for_amount(
        &self,
        amount: u64,
        _fee_rate: Option<u64>,
        _lock_utxos: bool,
    ) -> Result<Vec<Utxo>, ManagerError> {
        let unspent = self
            .bdk_wallet
            .list_unspent()
            .map_err(bdk_err_to_manager_err)?;
        let utxos_iter = unspent.iter().map(|utxo| {
            let addr =
                Address::from_script(&utxo.txout.script_pubkey, self.bdk_wallet.network()).unwrap();
            Utxo {
                tx_out: utxo.clone().txout,
                outpoint: utxo.clone().outpoint,
                address: addr,
                redeem_script: Script::new(),
            }
        });

        let mut accum: Vec<Utxo> = Vec::new();

        for utxo in utxos_iter {
            if accum.iter().map(|a| a.tx_out.value).sum::<u64>() > amount {
                return Ok(accum);
            } else {
                accum.push(utxo)
            }
        }

        let available: u64 = accum.iter().map(|a| a.tx_out.value).sum();
        Err(bdk_err_to_manager_err(bdk::Error::InsufficientFunds {
            needed: amount,
            available,
        }))
    }

    fn import_address(&self, _address: &Address) -> Result<(), ManagerError> {
        // todo is this okay?
        Ok(())
    }

    fn get_transaction(&self, tx_id: &Txid) -> Result<Transaction, ManagerError> {
        let tx_opt = self
            .bdk_wallet
            .get_tx(tx_id, true)
            .map_err(bdk_err_to_manager_err)?;

        match tx_opt {
            Some(tx) => Ok(tx.transaction.unwrap()),
            None => Err(bdk_err_to_manager_err(bdk::Error::TransactionNotFound)),
        }
    }

    fn get_transaction_confirmations(&self, tx_id: &Txid) -> Result<u32, ManagerError> {
        self.bdk_wallet
            .get_tx(tx_id, false)
            .map_err(bdk_err_to_manager_err)
            .and_then(|tx_opt| {
                let tx_details = tx_opt.unwrap();
                match tx_details.confirmation_time {
                    None => Err(err_to_manager_err(Error::MissingTransaction)),
                    Some(block_time) => {
                        let last_sync = self
                            .bdk_wallet
                            .database()
                            .get_sync_time()
                            .map_err(bdk_err_to_manager_err)?
                            .unwrap();

                        Ok(last_sync.block_time.height - block_time.height + 1)
                    }
                }
            })
    }
}
