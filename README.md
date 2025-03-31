# Distributed-File-System-Simulator
A distributed file system that ensures data availability and integrity across multiple nodes. The system should incorporate fault tolerance mechanisms to handle node failures gracefully.
This project is a Distributed File System (DFS) designed to store, manage, and retrieve files across multiple nodes in a network. It incorporates fault tolerance, ensuring data availability and reliability even in the event of node failures. The system distributes files across multiple storage nodes and replicates data to provide redundancy, minimizing the risk of data loss.

How It Works
File Distribution

Files uploaded to the system are divided into chunks and distributed across multiple storage nodes.

A metadata server keeps track of file locations, chunk assignments, and replication details.

Replication & Fault Tolerance

Each file chunk is replicated across multiple nodes to ensure data redundancy.

In case of node failure, the system retrieves the file from another available replica.

Automatic re-replication is triggered when a node failure is detected, maintaining the required level of redundancy.

Data Retrieval

When a user requests a file, the metadata server identifies the chunk locations and reconstructs the file by fetching data from multiple nodes.

Load balancing mechanisms ensure efficient access, distributing requests across available nodes.

Failure Detection & Recovery

A monitoring system constantly checks the health of storage nodes.

If a node fails, the system redistributes the affected data to healthy nodes.

Recovery mechanisms ensure minimal downtime and uninterrupted access to stored files.

Scalability & Performance

The system dynamically adds or removes nodes as needed to scale storage capacity.

Distributed architecture ensures high availability and efficient resource utilization.
