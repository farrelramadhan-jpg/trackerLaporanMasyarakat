from datetime import datetime
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class laporanBlock:
    def __init__(self, id, tipeTransaksi, isi, actorId, parentId = None, parentHash = None):
        self.id = id
        self.tipeTransaksi = tipeTransaksi
        self.isi = isi
        self.actorId = actorId
        self.parentId = parentId
        self.parentHash = parentHash
        self.timestamp = datetime.now().isoformat()
        self.signature = None

def computeHash(block):
    dataTanpaSignature = {k: v for k, v in block.__dict__.items() if k != 'signature'}
    payload = json.dumps(dataTanpaSignature, sort_keys=True).encode(encoding='utf-8', errors='strict')
    return hashlib.sha256(payload).hexdigest()

laporan1 = laporanBlock(1, 'LAPORAN_BARU', 'Jalan Rusak di jalan maleo', 'Warga01')

laporan2 = laporanBlock(2, 'UPDATE_STATUS', 'Status: diproses', 'DinasPU', parentId=laporan1.id)
laporan3 = laporanBlock(3, 'TANGGAPAN_RESMI', 'Perbaikan dijadwalkan minggu depan', 'DinasPU', parentId=laporan2.id)

laporan2.parentHash = computeHash(laporan1)
laporan3.parentHash = computeHash(laporan2)

def isChainValid(latestBlock):
    cur = latestBlock
    while cur is not None and cur.parentId is not None:
        parent = {
            1: laporan1,
            2: laporan2,
            3: laporan3
        }[cur.parentId]
        expected = computeHash(parent)
        if cur.parentHash != expected:
            return False
        cur = parent
    return True


privateKeyDinasPU = rsa.generate_private_key(public_exponent=65537, key_size = 2048)
publicKeyDinasPU = privateKeyDinasPU.public_key()

def signBlock(block, privateKey):
    dataTanpaSignature = {k: v for k, v in block.__dict__.items() if k != 'signature'}
    message = json.dumps(dataTanpaSignature, sort_keys=True).encode('utf-8')
    signature = privateKey.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    block.signature = signature

def verifyBlock(block, publicKey):
    dataTanpaSignature = {k: v for k, v in block.__dict__.items() if k != 'signature'}
    message = json.dumps(dataTanpaSignature, sort_keys=True).encode('utf-8')
    try:
        publicKey.verify(
            block.signature, message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


validatorTerdaftar = {
    'DinasPU': publicKeyDinasPU,
}

def validasiBlockBaru(block, chainBlocks):
    if block.actorId not in validatorTerdaftar:
        return False, "Aktor tidak terdaftar sebagai validator resmi"
    
    publicKeyPengirim = validatorTerdaftar[block.actorId]
    if not verifyBlock(block, publicKeyPengirim):
        return False, "Signature tidak valid"
    
    if block.parentId is not None:
        parent = chainBlocks[block.parentId]
        if block.parentHash != computeHash(parent):
            return False, "Parent hash tidak cocok, chain mungkin sudah dimanipulasi"
    
    return True, "Block sah dan disetujui masuk ke chain"

chainBlocks = {1: laporan1, 2: laporan2, 3: laporan3}

# Kasus valid
signBlock(laporan2, privateKeyDinasPU)
status, pesan = validasiBlockBaru(laporan2, chainBlocks)
print(status, "-", pesan)

# Kasus aktor tidak resmi
laporanPalsu = laporanBlock(4, 'UPDATE_STATUS', 'Status: selesai (palsu)', 'WargaIseng', parentId=3, parentHash=computeHash(laporan3))
status, pesan = validasiBlockBaru(laporanPalsu, chainBlocks)
print(status, "-", pesan)