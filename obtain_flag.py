# obtain_flag.py — varre TODAS as permutações dos 4 labels
import json
import hashlib
from itertools import permutations

from yao import evaluate_circuit
from public_data import g_tables

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# --------------------------------------------------------------------
# 1) carrega o circuito
with open("circuit.json", "r", encoding="utf-8") as f:
    circuit = json.load(f)

in_ids = circuit["inputs"]          # esperado [1,2,3,4]
assert len(in_ids) == 4, in_ids

# 2) seus quatro labels (substitua se for o caso)
LABELS = [11693387, 11338704, 7371799, 2815776]

# 3) tenta todas as 24 permutações
inputs = None
for idx, perm in enumerate(permutations(LABELS, 4), 1):
    trial_inputs = dict(zip(in_ids, perm))
    try:
        _ = evaluate_circuit(circuit, g_tables, trial_inputs)
        inputs = trial_inputs
        print(f"[+] Entradas válidas (perm #{idx}): {inputs}")
        break
    except ValueError:
        continue

if inputs is None:
    raise RuntimeError("Nenhuma permutação funcionou; verifique os labels.")

# --------------------------------------------------------------------
# 4) calcula a flag a partir das entradas válidas
msg = f"{inputs[in_ids[0]]}:{inputs[in_ids[1]]}:{inputs[in_ids[2]]}:{inputs[in_ids[3]]}".encode("ascii")
digest = hashlib.sha512(msg).digest()

xor_flag = b'\x90),u\x1b\x1dE:\xa8q\x91}&\xc7\x90\xbb\xce]\xf5\x17\x89\xd7\xfa\x07\x86\x83\xfa\x9b^\xcb\xd77\x00W\xca\xceXD7'
flag = xor_bytes(digest, xor_flag)

# 5) saída
print("\n[*] msg:", msg.decode("ascii"))
print("[*] SHA-512(msg):", digest.hex())
print("[*] FLAG (bytes):", flag)
try:
    print("[*] FLAG (ascii):", flag.decode("ascii"))
except UnicodeDecodeError:
    pass
