use cggmp24::generic_ec::NonZero;
use cggmp24::{
    aux_info_gen,
    key_refresh::PregeneratedPrimes,
    key_share::{IncompleteKeyShare, KeyShare, reconstruct_secret_key},
    keygen,
    security_level::SecurityLevel128,
    signing,
    signing::{DataToSign, Presignature},
    supported_curves::Secp256k1,
    ExecutionId,
};
use ethers::prelude::*;
use ethers::types::transaction::eip2718::TypedTransaction;
use round_based::state_machine::{ProceedResult, StateMachine};
use round_based::{Incoming, MessageDestination, MessageType};
use sha2::Digest;
use std::collections::HashMap;
use std::convert::TryFrom;
use tokio::sync::mpsc;

// 自定义消息结构用于模拟网络
#[derive(Clone)]
struct SimulationMsg<M> {
    sender: u16,
    receiver: Option<u16>,
    body: M,
}

// 模拟网络传输的辅助函数
// 在生产环境中，这里应该是 TCP/HTTP 请求
async fn simulate_network<P>(
    party_index: u16,
    mut protocol: P,
    tx_channels: HashMap<u16, mpsc::UnboundedSender<SimulationMsg<P::Msg>>>,
    mut rx_channel: mpsc::UnboundedReceiver<SimulationMsg<P::Msg>>,
) -> Result<P::Output, String>
where
    P: StateMachine,
    P::Msg: Clone,
{
    loop {
        match protocol.proceed() {
            ProceedResult::NeedsOneMoreMessage => {
                match rx_channel.recv().await {
                    Some(msg) => {
                        let incoming = Incoming {
                            id: 0,
                            sender: msg.sender,
                            msg_type: if msg.receiver.is_some() {
                                MessageType::P2P
                            } else {
                                MessageType::Broadcast
                            },
                            msg: msg.body,
                        };
                        if let Err(_e) = protocol.received_msg(incoming) {
                            panic!("Party {} received_msg error", party_index);
                        }
                        // 关键修复: 处理完消息后主动让出 CPU，防止连续计算导致其他任务饥饿
                        tokio::task::yield_now().await;
                    }
                    None => {
                        // 通道关闭时退出，防止死循环
                        return Err("channel closed".to_string());
                    }
                }
            }
            ProceedResult::SendMsg(outgoing) => { match outgoing.recipient {
                MessageDestination::OneParty(receiver) => {
                    if let Some(tx) = tx_channels.get(&receiver) {
                        tx.send(SimulationMsg {
                            sender: party_index,
                            receiver: Some(receiver),
                            body: outgoing.msg,
                        }).expect("Failed to send message");
                    }
                }
                MessageDestination::AllParties => {
                    for tx in tx_channels.values() {
                        tx.send(SimulationMsg {
                            sender: party_index,
                            receiver: None,
                            body: outgoing.msg.clone(),
                        }).expect("Failed to send broadcast");
                    }
                }
            }
            tokio::task::yield_now().await;
            },
            ProceedResult::Yielded => {
                tokio::task::yield_now().await;
            }
            ProceedResult::Output(result) => return Ok(result),
            ProceedResult::Error(_e) => return Err("Protocol error".to_string()),
        }
    }
}

#[tokio::main]
async fn main() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            println!("=== 开始 Lockness/CGGMP24 HD Wallet 演示 ===");

            // 设定 3 个参与方
            let n: u16 = 3;
            let t: u16 = 3; // 3-of-3 签名

            // ==========================================
            // 第一步: 获取 KeyShares (加载缓存 或 运行 DKG)
            // ==========================================
            let key_shares_file = "key_shares.json";
            let key_shares = if std::path::Path::new(key_shares_file).exists() {
                println!(
                    "\n[1] 发现本地密钥分片缓存 {}，正在加载...",
                    key_shares_file
                );
                let file = std::fs::File::open(key_shares_file).expect("无法打开密钥分片文件");
                let reader = std::io::BufReader::new(file);
                let shares: Vec<KeyShare<Secp256k1, SecurityLevel128>> =
                    serde_json::from_reader(reader).expect("无法解析密钥分片文件");
                if shares.len() != n as usize {
                    panic!(
                        "缓存文件中的分片数量 ({}) 与参与方数量 ({}) 不匹配",
                        shares.len(),
                        n
                    );
                }
                shares
            } else {
                // 1. 建立模拟网络通道 (仅在需要 DKG 时建立)
                let mut tx_channels = HashMap::new();
                let mut rx_channels = HashMap::new();
                let mut rxs = HashMap::new();

                for i in 0..n {
                    let (tx, rx) = mpsc::unbounded_channel();
                    rx_channels.insert(i, tx);
                    rxs.insert(i, rx);
                }

                for i in 0..n {
                    let mut my_txs = HashMap::new();
                    for j in 0..n {
                        my_txs.insert(j, rx_channels[&j].clone());
                    }
                    tx_channels.insert(i, my_txs);
                }

                // ==========================================
                // 第一步: DKG (分布式密钥生成)
                // ==========================================
                println!("\n[1] 正在运行 DKG 生成主密钥...");

                let eid = ExecutionId::new(b"lockness-demo-keygen");
                let mut keygen_handles = vec![];

                for i in 0..n {
                    let tx = tx_channels[&i].clone();
                    let rx = rxs.remove(&i).unwrap();
                    let eid = eid.clone();

                    // 启动 KeyGen 协议
                    keygen_handles.push(tokio::task::spawn_local(async move {
                        let protocol =
                            round_based::state_machine::wrap_protocol(|party| async move {
                                let mut rng = rand::rngs::OsRng;
                                keygen::<Secp256k1>(eid, i, n)
                                    .set_threshold(t)
                                    // [HD Wallet]: 开启 HD 支持。
                                    // 这一步会在 DKG 中并行生成 Chain Code。
                                    // 相比普通 DKG，这**不会增加任何额外的网络交互轮次** (0 rounds added)。
                                    .hd_wallet(true) // dkg hd wallet 关键参数
                                    .start(&mut rng, party)
                                    .await
                            });
                        simulate_network(i, protocol, tx, rx).await
                    }));
                }

                let mut incomplete_shares: Vec<IncompleteKeyShare<Secp256k1>> = vec![];
                for handle in keygen_handles {
                    incomplete_shares.push(
                        handle
                            .await
                            .unwrap()
                            .expect("Execution failed")
                            .expect("KeyGen failed"),
                    );
                }

                // ==========================================
                // 第一步.五: Aux Info Generation (生成签名所需的 Paillier 密钥)
                // ==========================================
                println!("\n[1.5] 正在运行 Aux Info Generation...");

                let cache_file = "pregenerated_primes.json";
                let pregenerated_primes = if std::path::Path::new(cache_file).exists() {
                    println!("  -> [提示] 发现本地缓存 {}，正在加载...", cache_file);
                    let file = std::fs::File::open(cache_file).expect("无法打开缓存文件");
                    let reader = std::io::BufReader::new(file);
                    let primes: Vec<PregeneratedPrimes<SecurityLevel128>> =
                        serde_json::from_reader(reader).expect("无法解析缓存文件");
                    if primes.len() != n as usize {
                        panic!(
                            "缓存文件中的素数数量 ({}) 与参与方数量 ({}) 不匹配",
                            primes.len(),
                            n
                        );
                    }
                    primes
                } else {
                    println!("  -> [提示] 正在并行生成素数，这可能需要几分钟，请耐心等待...");

                    let mut primes_handles = vec![];
                    for _ in 0..n {
                        primes_handles.push(tokio::task::spawn_blocking(|| {
                            let mut rng = rand::rngs::OsRng;
                            PregeneratedPrimes::<SecurityLevel128>::generate(&mut rng)
                        }));
                    }
                    let mut pregenerated_primes = vec![];
                    for handle in primes_handles {
                        pregenerated_primes.push(handle.await.unwrap());
                    }

                    println!("  -> 生成完成，正在保存到本地缓存 {}...", cache_file);
                    let file = std::fs::File::create(cache_file).expect("无法创建缓存文件");
                    let writer = std::io::BufWriter::new(file);
                    serde_json::to_writer(writer, &pregenerated_primes).expect("无法写入缓存文件");

                    pregenerated_primes
                };
                println!("  -> 素数准备就绪，开始执行协议...");

                let mut aux_handles = vec![];
                let aux_eid = ExecutionId::new(b"lockness-demo-aux");

                // 为 Aux 阶段重新建立模拟网络通道
                let mut aux_tx_channels = HashMap::new();
                let mut aux_rx_channels = HashMap::new();
                let mut aux_rxs = HashMap::new();

                // [Import Demo]: 克隆一份素数数据，供稍后 Trusted Dealer 导入演示使用
                let primes_for_import = pregenerated_primes.clone();

                for i in 0..n {
                    let (tx, rx) = mpsc::unbounded_channel();
                    aux_rx_channels.insert(i, tx);
                    aux_rxs.insert(i, rx);
                }

                for i in 0..n {
                    let mut my_txs = HashMap::new();
                    for j in 0..n {
                        my_txs.insert(j, aux_rx_channels[&j].clone());
                    }
                    aux_tx_channels.insert(i, my_txs);
                }

                for (i, primes) in (0..n).zip(pregenerated_primes.into_iter()) {
                    let tx = aux_tx_channels[&i].clone();
                    let rx = aux_rxs.remove(&i).unwrap();
                    let eid = aux_eid.clone();

                    aux_handles.push(tokio::task::spawn_local(async move {
                        let protocol =
                            round_based::state_machine::wrap_protocol(|party| async move {
                                let mut rng = rand::rngs::OsRng;
                                aux_info_gen::<SecurityLevel128>(eid, i, n, primes)
                                    .start(&mut rng, party)
                                    .await
                            });
                        simulate_network(i, protocol, tx, rx).await
                    }));
                }

                let mut key_shares: Vec<KeyShare<Secp256k1, SecurityLevel128>> = vec![];
                for (share, handle) in incomplete_shares.into_iter().zip(aux_handles) {
                    let aux_info = handle
                        .await
                        .unwrap()
                        .expect("Execution failed")
                        .expect("AuxInfo generation failed");
                    key_shares.push(KeyShare::from_parts((share, aux_info)).unwrap());
                }

                // 保存 KeyShares
                println!(">>> DKG 成功，正在保存密钥分片到 {}...", key_shares_file);
                let file = std::fs::File::create(key_shares_file).expect("无法创建密钥分片文件");
                let writer = std::io::BufWriter::new(file);
                serde_json::to_writer(writer, &key_shares).expect("无法写入密钥分片文件");

                // ==========================================
                // [演示] 立即使用 Trusted Dealer 导入刚才生成的私钥
                // ==========================================
                // 注意：这只是为了演示 Import 功能。在实际场景中，你可能是在另一台机器上，
                // 或者从冷存储中读取私钥，然后通过 Trusted Dealer 拆分。
                println!("\n[Demo] 正在演示 Trusted Dealer 密钥导入 (Import Key)...");
                // 假设我们从某个地方获取了私钥 (这里直接使用 key_shares[0] 对应的私钥，仅作演示)
                // 在实际恢复流程中，你会使用 reconstruct_secret_key 恢复出的 secret_scalar
                let _secret_scalar = key_shares[0].core.x.clone(); 
                // 实际上 DKG 生成的私钥是分布式的，这里我们只是为了演示 Trusted Dealer 的 API。
                // 为了演示真实性，我们稍后会在 Step 6 使用 reconstruct 出来的完整私钥进行导入。
                
                // 将素数数据保存下来给 Step 6 使用
                // 由于 Rust 的所有权机制，我们需要把 primes_for_import 传递出去或者保存到文件
                // 这里为了简单，我们将它序列化保存，稍后读取
                let import_primes_file = "pregenerated_primes.json";
                let file = std::fs::File::create(import_primes_file).unwrap();
                serde_json::to_writer(file, &primes_for_import).unwrap();

                key_shares
            };

            let root_pubkey = key_shares[0].core.key_info.shared_public_key;
            println!(">>> 密钥分片准备就绪!");
            println!(
                ">>> 主公钥 (Root PubKey): {:?}",
                hex::encode(root_pubkey.to_bytes(true))
            );

            // 计算主公钥的 ETH 地址
            let root_uncompressed = root_pubkey.to_bytes(false);
            let mut hasher = sha3::Keccak256::new();
            hasher.update(&root_uncompressed[1..]); // 去掉 0x04 前缀
            let root_eth_addr = &hasher.finalize()[12..]; // 取后 20 字节
            println!(
                ">>> 主公钥 (Root PubKey) 对应的以太坊地址: 0x{}",
                hex::encode(root_eth_addr)
            );

            // 检查是否生成了 Chain Code (HD Wallet 必须)
            // 有了这个 Chain Code，才能组合出 BIP32 Extended Public Key (xpub)。
            if let Some(cc) = key_shares[0].core.key_info.chain_code {
                println!(">>> Chain Code 已生成: {:?}", hex::encode(cc));
            } else {
                panic!("错误: 未生成 Chain Code");
            }

            // ==========================================
            // 插入: 计算并显示 m/0/0 的以太坊地址
            // ==========================================
            let root_pubkey_bytes = root_pubkey.to_bytes(true);
            let chain_code_bytes = key_shares[0].core.key_info.chain_code.unwrap();

            let xpub = bitcoin::bip32::Xpub {
                network: bitcoin::Network::Bitcoin.into(),
                depth: 0,
                parent_fingerprint: bitcoin::bip32::Fingerprint::default(),
                child_number: bitcoin::bip32::ChildNumber::from_normal_idx(0).unwrap(),
                public_key: bitcoin::secp256k1::PublicKey::from_slice(&root_pubkey_bytes).unwrap(),
                chain_code: bitcoin::bip32::ChainCode::from(chain_code_bytes),
            };

            // 2. 衍生 m/0/0 子公钥
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let child_path = "m/0/0".parse::<bitcoin::bip32::DerivationPath>().unwrap();
            // HMAC-SHA512 产生的结果是 64 字节，它被一分为二。左边 32 字节是 Tweak（用于生成当前子钥），右边 32 字节是 新的 Chain Code（用于生成下一代孙钥）。
            // I_L (Left 32-bytes): 密钥偏移量 (The Tweak)
            // 这是用来修改父密钥以生成子密钥的数值。
            // 作用: 它被解析为一个大整数（Scalar）。
            // 数学运算:
            // 对于公钥: 子公钥 = 父公钥 + (I_L . 基点 G)。这是 xpub.derive_pub 做的事情。
            // 对于私钥: 子私钥 = (父私钥 + I_L) mod n 在 MPC 中，这意味着每个参与方都要把这个 I_L 加到自己的私钥分片上（通过同态加密或本地计算），从而让大家共同拥有子私钥的分片。
            // 2. I_R (Right 32-bytes): 子链码 (Child Chain Code)
            // 这是传递给下一层级的熵（Entropy）或“盐”。

            // 作用: 它直接成为子扩展密钥（Extended Key）中的 chain_code 部分。
            // 意义: 如果没有链码，每次衍生只依赖公钥和索引，安全性会降低。I_R 确保了每一层级的衍生都引入了新的随机性（源自上一层的 HMAC 运算），
            // 使得推导孙密钥（Grandchild）时需要依赖这个新的链码，而不是复用父节点的链码。


            // cggmp24 计算 HMAC-SHA512: 
            // 输入是父公钥 (xpub.public_key)、父链码 (xpub.chain_code) 和索引 (child_path)
            let child_xpub = xpub.derive_pub(&secp, &child_path).unwrap();

            // 3. 计算以太坊地址
            let uncompressed_pk = child_xpub.public_key.serialize_uncompressed();
            let mut hasher = sha3::Keccak256::new();
            hasher.update(&uncompressed_pk[1..]); // 去掉 0x04 前缀
            let eth_addr_bytes = &hasher.finalize()[12..]; // 取后 20 字节
            println!(
                ">>> [User Info] m/0/0 对应的以太坊地址: 0x{}",
                hex::encode(eth_addr_bytes)
            );

            // ==========================================
            // 第二步: 准备 HD Derivation 路径
            // ==========================================
            // 定义路径 m/0/0 (非强化衍生)
            // 注意: cggmp24 目前仅支持非强化衍生 (Normal Derivation)
            let path: Vec<u32> = vec![0, 0];
            println!("\n[2] 准备对路径 m/0/0 进行签名...");
            println!("注意: 这里不需要重新运行 DKG, 直接使用主分片进行计算。");

            // ==========================================
            // Step 2.5: Pre-signing (Offline Phase)
            // ==========================================
            println!("\n[2.5] 正在运行 Pre-signing (预签名)...");
            println!("说明: Presign 阶段生成与消息无关的随机数 (Nonces)，支持 HD Wallet (在 Signing 阶段应用路径)。");

            let mut tx_channels_presign = HashMap::new();
            let mut rx_channels_presign = HashMap::new();
            let mut rxs_presign = HashMap::new();

            for i in 0..n {
                let (tx, rx) = mpsc::unbounded_channel();
                rx_channels_presign.insert(i, tx);
                rxs_presign.insert(i, rx);
            }
            for i in 0..n {
                let mut my_txs = HashMap::new();
                for j in 0..n {
                    my_txs.insert(j, rx_channels_presign[&j].clone());
                }
                tx_channels_presign.insert(i, my_txs);
            }

            let presign_eid = ExecutionId::new(b"lockness-demo-presign");
            let mut presign_handles = vec![];

            for i in 0..n {
                let key_share = key_shares[i as usize].clone();
                let tx = tx_channels_presign[&i].clone();
                let rx = rxs_presign.remove(&i).unwrap();
                let eid = presign_eid.clone();

                presign_handles.push(tokio::task::spawn_local(async move {
                    let protocol = round_based::state_machine::wrap_protocol(|party| async move {
                        let mut rng = rand::rngs::OsRng;
                        signing::<Secp256k1, SecurityLevel128>(eid, i, &[0, 1, 2], &key_share)
                            .generate_presignature(&mut rng, party)
                            .await
                    });
                    simulate_network(i, protocol, tx, rx).await
                }));
            }

            let mut presignatures = vec![];
            for handle in presign_handles {
                presignatures.push(
                    handle
                        .await
                        .unwrap()
                        .expect("Execution failed")
                        .expect("Presigning failed"),
                );
            }
            println!(">>> Pre-signing 完成! 获得 {} 份预签名数据。", presignatures.len());

            // ==========================================
            // 第三步: 签名 (带 Derivation Path)
            // ==========================================

            // 重置网络通道 (为了演示简单，重新建立通道)
            let mut tx_channels_sign = HashMap::new();
            let mut rx_channels_sign = HashMap::new();
            let mut rxs_sign = HashMap::new();

            for i in 0..n {
                let (tx, rx) = mpsc::unbounded_channel();
                rx_channels_sign.insert(i, tx);
                rxs_sign.insert(i, rx);
            }
            for i in 0..n {
                let mut my_txs = HashMap::new();
                for j in 0..n {
                    my_txs.insert(j, rx_channels_sign[&j].clone());
                }
                tx_channels_sign.insert(i, my_txs);
            }

            // ==========================================
            // 3.1 构建以太坊交易 (EIP-1559)
            // ==========================================
            // 连接到 Sepolia 测试网 (或其他 RPC)
            let rpc_url = "https://ethereum-sepolia-rpc.publicnode.com";
            let provider = Provider::<Http>::try_from(rpc_url).expect("Invalid RPC URL");
            let chain_id = 11155111u64; // Sepolia Chain ID

            let from_addr = Address::from_slice(eth_addr_bytes);
            let to_addr: Address = "0x945ffa853f241ee857353cf4ffce0c338377e5d3"
                .parse()
                .unwrap();

            // 获取 Nonce (如果网络不通，这里可能会失败，生产环境需处理错误)
            println!(">>> 正在从网络获取 Nonce (Sender: {:?})...", from_addr);
            let nonce = provider
                .get_transaction_count(from_addr, None)
                .await
                .unwrap_or(U256::zero());

            let tx_request = Eip1559TransactionRequest::new()
                .to(to_addr)
                .value(100) // 100 Wei
                .nonce(nonce)
                .chain_id(chain_id)
                .gas(21000) // 必须显式设置 Gas Limit，标准转账为 21000
                .max_priority_fee_per_gas(1_000_000_000u64) // 1 gwei
                .max_fee_per_gas(20_000_000_000u64); // 20 gwei

            let tx: TypedTransaction = tx_request.into();
            let sighash = tx.sighash();
            let message_to_sign = *sighash.as_fixed_bytes();
            println!(
                ">>> 待签名交易 Hash (Sighash): 0x{}",
                hex::encode(message_to_sign)
            );
            let tx_rlp = tx.rlp();

            let mut sign_handles = vec![];
            let sign_eid = ExecutionId::new(b"lockness-demo-signing");

            for i in 0..n {
                let key_share = key_shares[i as usize].clone();
                let tx = tx_channels_sign[&i].clone();
                let rx = rxs_sign.remove(&i).unwrap();
                let path = path.clone();
                let eid = sign_eid.clone();
                let tx_rlp = tx_rlp.clone();
                let _presignature = presignatures[i as usize].clone();

                sign_handles.push(tokio::task::spawn_local(async move {
                    // 关键代码在这里 !!!
                    // 使用 set_derivation_path 将签名目标指向子地址
                    let protocol = round_based::state_machine::wrap_protocol(|party| async move {
                        let mut rng = rand::rngs::OsRng;
                        signing::<Secp256k1, SecurityLevel128>(eid, i, &[0, 1, 2], &key_share)
                            // 私钥衍生发生在这里
                            // 这一步会计算 Tweak (I_L)，并将其应用到各方的私钥分片上
                            // 从而实现: 子私钥签名 = (父私钥 + I_L) 签名
                            // 这是一个纯本地计算 (Local Operation)，因为输入(公钥,链码)都是公开的。
                            // 因此，相比普通签名，这不会增加任何额外的网络交互轮次
                            .set_derivation_path_with_algo::<cggmp24::hd_wallet::Slip10, _>(path)
                            .expect("Derivation path error")
                            .sign(
                                &mut rng,
                                party,
                                &DataToSign::from_digest(sha3::Keccak256::new_with_prefix(tx_rlp)),
                            )
                            .await
                    });

                    simulate_network(i, protocol, tx, rx).await
                }));
            }

            let mut signatures = vec![];
            for handle in sign_handles {
                signatures.push(
                    handle
                        .await
                        .unwrap()
                        .expect("Execution failed")
                        .expect("Signing failed"),
                );
            }

            let sig = &signatures[0];
            println!("\n[3] 签名完成!");
            println!(">>> R: {:?}", hex::encode(sig.r.to_be_bytes()));
            println!(">>> S: {:?}", hex::encode(sig.s.to_be_bytes()));

            // ==========================================
            // 第四步: 验证 (Verify)
            // ==========================================
            println!("\n[4] 组装交易并广播...");

            let r = U256::from_big_endian(&sig.r.to_be_bytes());
            let s = U256::from_big_endian(&sig.s.to_be_bytes());

            // 计算 Recovery ID (v)
            // MPC 协议通常只返回 r 和 s。我们需要尝试 v=0 和 v=1，看哪个能恢复出正确的发送方地址。
            let mut v = 0;
            let mut recovered_correctly = false;

            for rec_id in 0..4 {
                let signature = Signature { r, s, v: rec_id };
                // 尝试恢复地址
                if let Ok(recovered_addr) = signature.recover(sighash) {
                    if recovered_addr == from_addr {
                        v = rec_id;
                        recovered_correctly = true;
                        println!(">>> 成功恢复公钥,Recovery ID (v) = {}", v);
                        break;
                    }
                }
            }

            if !recovered_correctly {
                println!("!!! 警告: 无法从签名恢复出正确的发送方地址，签名可能无效。");
            } else {
                // 组装最终的签名交易
                let signature = Signature { r, s, v };
                let signed_tx_bytes = tx.rlp_signed(&signature);
                let signed_tx_hex = hex::encode(&signed_tx_bytes);
                println!(">>> 已签名交易 (RLP Hex): 0x{}", signed_tx_hex);

                // 广播交易
                println!(">>> 正在广播交易...");
                match provider
                    .send_raw_transaction(Bytes::from(signed_tx_bytes))
                    .await
                {
                    Ok(pending_tx) => {
                        println!(">>> 交易发送成功! Hash: {:?}", pending_tx.tx_hash())
                    }
                    Err(e) => println!("!!! 交易发送失败: {:?}", e),
                }
            }

            // ==========================================
            // 第五步: 导出私钥 (Export Private Key)
            // ==========================================
            println!("\n[5] 正在尝试恢复/导出私钥 (Reconstruct Secret Key)...");
            // 只需要 t 个分片即可恢复
            let shares_for_recovery = &key_shares[0..t as usize];

            // 使用 cggmp24 提供的工具函数恢复私钥
            // reconstruct_secret_key 函数的作用是通过拉格朗日插值法从多个分片中恢复出数学上的私钥标量 (Secret Scalar)。
            // 由于 chain_code 在所有分片中都是明文且一致的，不需要进行数学恢复，所以该函数只返回计算出的私钥标量
            let reconstructed_sk = reconstruct_secret_key(shares_for_recovery)
                .expect("私钥恢复失败");
            
            // 获取私钥字节 (Big-Endian)
            let secret_bytes = reconstructed_sk.as_ref().to_be_bytes();
            println!(">>> 主私钥 (Master Private Key): {}", hex::encode(&secret_bytes));

            // 构造 BIP32 Extended Private Key (xprv) 以便衍生子私钥
            if let Some(cc) = key_shares[0].core.key_info.chain_code {
                let xprv = bitcoin::bip32::Xpriv {
                    network: bitcoin::Network::Bitcoin.into(),
                    depth: 0,
                    parent_fingerprint: bitcoin::bip32::Fingerprint::default(),
                    child_number: bitcoin::bip32::ChildNumber::from_normal_idx(0).unwrap(),
                    private_key: bitcoin::secp256k1::SecretKey::from_slice(&secret_bytes).unwrap(),
                    chain_code: bitcoin::bip32::ChainCode::from(cc),
                };
                println!(">>> Chain Code: {}", hex::encode(cc));
                println!(">>> 主扩展私钥 (Root xprv): {}", xprv);
                
                let child_path = "m/0/0".parse::<bitcoin::bip32::DerivationPath>().unwrap();
                let child_xprv = xprv.derive_priv(&secp, &child_path).unwrap();
                println!(">>> m/0/0 子私钥: {}", hex::encode(child_xprv.private_key.secret_bytes()));
            }

            // ==========================================
            // 第六步: 导入私钥 (Import Key via Trusted Dealer)
            // ==========================================
            println!("\n[6] 演示 Trusted Dealer 密钥导入 (Import Key)...");
            println!(">>> 正在使用 Step 5 恢复出的主私钥生成新的密钥分片...");
            
            // 1. 准备要导入的私钥 (NonZero<SecretScalar>)
            let non_zero_secret = NonZero::from_secret_scalar(reconstructed_sk)
                .expect("私钥不能为零");

            // 2. 加载预生成的素数 (为了加速演示，避免重新生成素数)
            let import_primes_file = "pregenerated_primes.json";
            let primes_for_import: Vec<PregeneratedPrimes<SecurityLevel128>> = 
                if std::path::Path::new(import_primes_file).exists() {
                    let file = std::fs::File::open(import_primes_file).unwrap();
                    serde_json::from_reader(file).unwrap()
                } else {
                    println!("(未找到预生成素数缓存，跳过导入演示或需要漫长等待)");
                    return;
                };

            // 获取 Chain Code (用于恢复 HD 钱包)
            let chain_code = key_shares[0].core.key_info.chain_code
                .expect("无法获取 Chain Code, 无法进行 HD 钱包恢复");

            // 3. 运行 Trusted Dealer
            let mut rng = rand::rngs::OsRng;
            let imported_shares = cggmp24::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(n)
                .set_threshold(Some(t))
                .set_shared_secret_key(non_zero_secret)
                .set_pregenerated_primes(primes_for_import) // 关键：复用素数，否则会卡住几分钟
                .hd_wallet(true) // 关键：开启 HD 支持，否则无法衍生子钥
                .generate_shares(&mut rng)
                .expect("Trusted Dealer 生成失败");   

            println!(">>> 导入成功! 生成了 {} 个新的密钥分片。", imported_shares.len());
            println!(">>> 新分片 0 的公钥: {}", hex::encode(imported_shares[0].core.key_info.shared_public_key.to_bytes(true)));
            println!(">>> (验证: 此公钥应与 Step 1 的 Root PubKey 完全一致)");
    
        })
        .await;
}
