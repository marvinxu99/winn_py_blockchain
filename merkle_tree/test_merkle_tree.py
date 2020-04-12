from merkle_tree import MerkleTree, verify_audit_trail


file = '01234567'
chunks = list(file)
merkle_tree = MerkleTree(chunks)
print("root hash=", merkle_tree.root.hash)

chunk_hash = MerkleTree.compute_hash("2")
print("Hash of '2' is:", chunk_hash)
audit_trail = merkle_tree.get_audit_trail(chunk_hash) 
print("audit trail:", audit_trail) 

print('start verify:')
result = verify_audit_trail(chunk_hash, audit_trail)
print(result)