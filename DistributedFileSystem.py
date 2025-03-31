class DFS:
    def __init__(self, num_nodes=3, replication_factor=2, chunk_size=1024):
        self.nodes = [Node(i) for i in range(num_nodes)]
        self.replication_factor = min(replication_factor, num_nodes)
        self.status_queue = Queue()
        self.original_hashes = {}
        self.original_files = {}
        self.chunk_size = chunk_size
        self.encryption_keys = {}

    def store_file(self, filename, data, retries=2, encrypt=False, password=None):
        attempt = 0
        while attempt <= retries:
            active_nodes = [node for node in self.nodes if node.active]
            if len(active_nodes) < self.replication_factor:
                self.status_queue.put(f"Error: Not enough active nodes ({len(active_nodes)}) for {filename}. Retrying...")
                attempt += 1
                time.sleep(1)
                continue
            
            original_data = data
            if encrypt and password:
                key = Fernet.generate_key()  # Simplified; should derive from password
                cipher = Fernet(key)
                data = cipher.encrypt(data)
                self.encryption_keys[filename] = key
                self.status_queue.put(f"[Encrypted] {filename}")

            chunks = [data[i:i + self.chunk_size] for i in range(0, len(data), self.chunk_size)]
            chunk_map = {}
            for i, chunk in enumerate(chunks):
                chunk_id = f"{filename}_chunk_{i}"
                checksum = hashlib.sha256(chunk).hexdigest()
                selected_nodes = random.sample(active_nodes, self.replication_factor)
                for node in selected_nodes:
                    node.store(chunk_id, chunk, checksum)
                chunk_map[chunk_id] = [node.node_id for node in selected_nodes]
            
            self.original_hashes[filename] = hashlib.sha256(data).hexdigest()
            self.original_files[filename] = original_data
            self.status_queue.put(f"Stored {filename} ({len(chunks)} chunks) on nodes: {chunk_map}")
            return True
        self.status_queue.put(f"Failed to store {filename} after {retries} retries")
        return False

    def retrieve_file(self, filename, decrypt=False, password=None):
        chunks = []
        chunk_id = 0
        while True:
            chunk_name = f"{filename}_chunk_{chunk_id}"
            chunk_data = None
            for node in self.nodes:
                data = node.retrieve(chunk_name)
                if data is not None:
                    chunks.append(data)
                    chunk_data = data
                    break
            if chunk_data is None:
                if chunk_id == 0:
                    self.status_queue.put(f"Error: No chunks of {filename} found")
                break
            chunk_id += 1
        
        if not chunks:
            self.status_queue.put(f"Error: {filename} retrieval failed - no data retrieved")
            return None
        
        full_data = b''.join(chunks)
        if decrypt and filename in self.encryption_keys:
            try:
                cipher = Fernet(self.encryption_keys[filename])
                full_data = cipher.decrypt(full_data)
                self.status_queue.put(f"[Decrypted] {filename}")
            except Exception as e:
                self.status_queue.put(f"Error: Decryption failed for {filename} - {str(e)}")
                return None
        self.status_queue.put(f"Retrieved {filename} ({len(chunks)} chunks)")
        return full_data

    def delete_file(self, filename):
        chunk_id = 0
        deleted = False
        while True:
            chunk_name = f"{filename}_chunk_{chunk_id}"
            found = False
            for node in self.nodes:
                if node.delete(chunk_name):
                    found = True
                    deleted = True
            if not found:
                break
            chunk_id += 1
        
        if deleted:
            if filename in self.original_hashes:
                del self.original_hashes[filename]
            if filename in self.original_files:
                del self.original_files[filename]
            if filename in self.encryption_keys:
                del self.encryption_keys[filename]
            self.status_queue.put(f"Deleted {filename} from all nodes")
            return True
        self.status_queue.put(f"Error: {filename} not found for deletion")
        return False

    def list_files(self):
        files = {}
        for node in self.nodes:
            for chunk_name in node.storage:
                filename = chunk_name.split('_chunk_')[0]
                if filename not in files:
                    files[filename] = set()
                files[filename].add(node.node_id)
        return files

    def simulate_node_failure(self, node_id):
        if 0 <= node_id < len(self.nodes):
            self.nodes[node_id].fail()
            self.status_queue.put(f"Node {node_id} failed")
            return True
        return False

    def recover_node(self, node_id):
        if 0 <= node_id < len(self.nodes):
            self.nodes[node_id].recover()
            self.status_queue.put(f"Node {node_id} recovered")
            return True
        return False
