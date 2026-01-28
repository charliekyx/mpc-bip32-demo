import binascii
import hashlib
import hmac
from ecdsa import SECP256k1, VerifyingKey


# === 配置区域 (来自 sample_out.txt) ===
# 这里的公钥和 Chain Code 是 DKG 生成的根信息
ROOT_PUB_KEY_HEX = "03236a27736a0eecb65c2dc337b2754fb67a27915f74244fd0bf44de994a015c8a"
ROOT_CHAIN_CODE_HEX = "81329bb243a28c436402a5e9d04c9377115ac95a31682958cc46e4997cb69fae"

# 待验证的签名信息 (来自 m/0/0)
MESSAGE = "Hello, HD Wallet!"
SIG_R_HEX = "4d40acb5d3d8f3d777351aaa8e4f672a27e05df6b46e6da756d8c91a665626c5"
SIG_S_HEX = "6777775996f4c1cecdd550b75cbe10902a9c249ca593e308e5b268c0b927e4ff"

# 衍生路径 m/0/0
DERIVATION_PATH = [0, 0]

def derive_child_pubkey(parent_pub_hex, parent_chain_hex, index):
    """
    实现 BIP32 的 CKDpub (Public Parent -> Public Child) 衍生函数
    """
    # 1. 准备输入数据
    # Data = ser_P(P) || ser_32(i)
    parent_pub_bytes = binascii.unhexlify(parent_pub_hex)
    parent_chain_bytes = binascii.unhexlify(parent_chain_hex)
    index_bytes = index.to_bytes(4, 'big')
    
    data = parent_pub_bytes + index_bytes
    
    # 2. HMAC-SHA512
    # Key = parent_chain_code
    # Data = data
    I = hmac.new(parent_chain_bytes, data, hashlib.sha512).digest()
    Il = I[:32] # 左半部分用于计算 tweak
    Ir = I[32:] # 右半部分作为子链码
    
    # 3. 计算子公钥
    # Child_Point = Parent_Point + Il * G
    
    il_int = int.from_bytes(Il, 'big')
    if il_int >= SECP256k1.order:
        raise ValueError("Il >= n (无效的衍生，概率极低)")
        
    # 计算偏移点 Il * G
    tweak_point = SECP256k1.generator * il_int
    
    # 解析父公钥点
    parent_vk = VerifyingKey.from_string(parent_pub_bytes, curve=SECP256k1)
    parent_point = parent_vk.pubkey.point
    
    # 点加法
    child_point = parent_point + tweak_point
    
    # 序列化回压缩格式 hex
    child_vk = VerifyingKey.from_public_point(child_point, curve=SECP256k1)
    child_pub_hex = binascii.hexlify(child_vk.to_string(encoding="compressed")).decode()
    child_chain_hex = binascii.hexlify(Ir).decode()
    
    return child_pub_hex, child_chain_hex

def main():
    print("=== BIP32 独立验证工具 ===")
    print(f"根公钥 (Root PubKey): {ROOT_PUB_KEY_HEX}")
    print(f"根链码 (Root ChainCode): {ROOT_CHAIN_CODE_HEX}")
    print("-" * 40)

    # 1. 执行衍生
    curr_pub = ROOT_PUB_KEY_HEX
    curr_cc = ROOT_CHAIN_CODE_HEX
    
    path_str = "m"
    for idx in DERIVATION_PATH:
        path_str += f"/{idx}"
        print(f"正在计算路径 {path_str} ...")
        curr_pub, curr_cc = derive_child_pubkey(curr_pub, curr_cc, idx)
        print(f"  -> 衍生公钥: {curr_pub}")
        print(f"  -> 衍生链码: {curr_cc}")

    final_pub = curr_pub
    print("-" * 40)
    print(f"最终推导出的公钥 (m/0/0): {final_pub}")
    
    # 2. 验证签名
    print("\n=== 验证签名 ===")
    # 假设消息使用 SHA256 哈希 (标准做法)
    msg_hash = hashlib.sha256(MESSAGE.encode('utf-8')).digest()
    print(f"消息: \"{MESSAGE}\"")
    print(f"消息哈希 (SHA256): {binascii.hexlify(msg_hash).decode()}")
    
    # 组合 R 和 S
    sig_bytes = binascii.unhexlify(SIG_R_HEX + SIG_S_HEX)
    
    # 构建验证键
    vk = VerifyingKey.from_string(binascii.unhexlify(final_pub), curve=SECP256k1)
    
    try:
        # 验证
        if vk.verify_digest(sig_bytes, msg_hash):
            print("\n>>> ✅ 验证成功 (SUCCESS) <<<")
            print("结论: 你的 MPC 代码生成的签名与标准 BIP32 推导出的公钥完全匹配。")
            print("这意味着你的 MPC 协议正确实现了 BIP32 的数学逻辑。")
    except Exception as e:
        print(f"\n>>> ❌ 验证失败 (FAILED): {e}")
        print("可能原因: 消息哈希算法不一致 (如使用了 Keccak256) 或衍生逻辑错误。")

if __name__ == "__main__":
    main()