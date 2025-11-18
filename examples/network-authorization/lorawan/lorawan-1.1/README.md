# LoRaWAN 1.1 Authorization Policy

Authorization policy for LoRaWAN 1.1 - Security improvements

## Overview

This policy implements authorization controls for LoRaWAN 1.1, ensuring:
- Secure device authentication
- Access control and authorization
- Resource allocation and management
- Anomaly detection and prevention

## Features

- **Device Authentication**: Validates device credentials
- **Connection Control**: Manages device connections
- **Data Transmission**: Controls data transfer permissions
- **Resource Management**: Allocates network resources

## Quick Start

```bash
# Start OPA server
make up

# Test authentication
make test-auth

# View logs
make logs
```

## Policy Rules

### Authentication
Devices must provide valid credentials to authenticate.

### Connection
Only authenticated devices can connect to the network.

### Data Transmission
Data transfer is authorized based on device quotas.

## Testing

```bash
# Run OPA tests
make test

# Query policy
curl -X POST http://localhost:8181/v1/data/lorawan_1.1/allow \
  -d '{"input": {"action": "authenticate", "device": {"id": "device-001"}}}'
```

## Resources

- Protocol specifications
- Security best practices
- Integration guides

## License

MIT
