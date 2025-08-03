# DQNSB Getting Started Guide

This guide provides instructions for setting up and contributing to the DQNSB (Deep Q-Network Secure Blockchain) project.

## Prerequisites

- Go 1.18 or higher
- Docker and Docker Compose
- Git
- Python 3.8+ (for DQN training and analysis)

## Setting Up the Development Environment

### 1. Clone the Repository

```bash
git clone https://github.com/0xharryriddle/DQNSB_Scheme.git
cd DQNSB_Scheme
```

### 2. Install Dependencies

```bash
# Install Go dependencies
go mod tidy

# Install Python dependencies for DQN components
pip install -r requirements.txt
```

### 3. Build the Project

```bash
make build
```

This will compile the Go code and generate the necessary binaries in the `bin` directory.

### 4. Run Tests

```bash
make test
```

This will run the unit tests to verify that everything is working correctly.

## Project Structure

```
DQNSB_Scheme/
├── src/                    # Source code
│   ├── main.go             # Application entry point
│   ├── consensus/          # Consensus protocols
│   │   ├── pbft/           # PBFT implementation
│   │   └── pos/            # Proof-of-Stake implementation
│   ├── node/               # Node implementation
│   ├── blockchain/         # Core blockchain components
│   ├── sharding/           # Sharding mechanisms
│   ├── dqn/                # DQN optimization framework
│   ├── network/            # P2P networking
│   └── api/                # API interfaces
├── cmd/                    # Command-line tools
├── scripts/                # Utility scripts
├── docs/                   # Documentation
├── tests/                  # Test suites
│   ├── unit/               # Unit tests
│   ├── integration/        # Integration tests
│   ├── performance/        # Performance benchmarks
│   └── security/           # Security tests
├── configs/                # Configuration files
├── docker/                 # Docker configurations
├── bin/                    # Compiled binaries
└── data/                   # Data directory for runtime
```

## Running a Local Node

### 1. Generate Configuration

```bash
./bin/dqnsb init --config ./configs/local.yaml
```

This will generate a local configuration file with default settings.

### 2. Start a Single Node

```bash
./bin/dqnsb start --config ./configs/local.yaml
```

### 3. Start a Local Test Network

```bash
docker-compose -f docker/docker-compose.yaml up
```

This will start a local test network with multiple nodes.

## Development Workflow

### 1. Creating a New Feature

1. Create a new branch from `main`:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Implement your changes and write tests

3. Ensure tests pass:

   ```bash
   make test
   ```

4. Format and lint your code:

   ```bash
   make fmt
   make lint
   ```

5. Commit your changes:

   ```bash
   git commit -m "Add feature: your feature description"
   ```

6. Push to your branch:

   ```bash
   git push origin feature/your-feature-name
   ```

7. Create a Pull Request in GitHub

### 2. Implementing a New Component

When implementing a new component:

1. Define the interface in the appropriate package
2. Implement the interface with tests
3. Update the main application to use the new component
4. Document the component in the technical documentation

## DQN Training and Optimization

### 1. Prepare Training Data

```bash
python scripts/prepare_training_data.py --output data/training
```

### 2. Train the DQN Model

```bash
python scripts/train_dqn.py --data data/training --output models/dqn_model
```

### 3. Evaluate the Model

```bash
python scripts/evaluate_dqn.py --model models/dqn_model --test-data data/test
```

### 4. Export the Model for Go Integration

```bash
python scripts/export_model.py --model models/dqn_model --output src/dqn/model
```

## Monitoring and Debugging

### 1. Access Node Metrics

```bash
curl http://localhost:8080/metrics
```

### 2. View Logs

```bash
./bin/dqnsb logs --level debug
```

### 3. Use the Debug Console

```bash
./bin/dqnsb console --node-id node1
```

## Common Tasks

### Adding a New Consensus Algorithm

1. Define the interface in `src/consensus/consensus.go`
2. Create a new package in `src/consensus/your_algorithm/`
3. Implement the consensus interface
4. Register your algorithm in `src/consensus/registry.go`
5. Add configuration options in `configs/`

### Modifying the DQN Model

1. Update the state representation in `src/dqn/state.go`
2. Update the action space in `src/dqn/action.go`
3. Modify the reward function in `src/dqn/reward.go`
4. Retrain the model using the Python scripts

### Adding a New API Endpoint

1. Define the endpoint in `src/api/routes.go`
2. Implement the handler in `src/api/handlers/`
3. Add tests in `tests/unit/api/`
4. Update the API documentation

## Troubleshooting

### Common Issues

1. **Compilation Errors**

   - Ensure you have the correct Go version
   - Run `go mod tidy` to update dependencies

2. **Node Not Connecting to Network**

   - Check your firewall settings
   - Verify the bootstrap nodes are accessible

3. **Consensus Not Progressing**

   - Check logs for timeout issues
   - Ensure enough validator nodes are running

4. **DQN Model Not Loading**
   - Check model format compatibility
   - Verify the model path is correct

### Getting Help

- Open an issue on GitHub for bugs or feature requests
- Join our developer Discord channel for real-time assistance
- Check the documentation for guidance on specific topics

## Additional Resources

- [Full API Documentation](docs/API.md)
- [Consensus Protocol Details](docs/CONSENSUS.md)
- [DQN Integration Guide](docs/DQN.md)
- [Sharding Protocol Specification](docs/SHARDING.md)
- [Security Considerations](docs/SECURITY.md)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
