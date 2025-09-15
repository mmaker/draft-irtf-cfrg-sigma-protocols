# sigma-protocols-py: Pure Python Sigma Protocols

A pure Python implementation of Sigma protocols.

## Installation

### Development Installation

```bash
git clone <repository-url>
cd sigma-protocols-py
pip install -e .
```

### From PyPI (when published)

```bash
pip install sigma-protocols-py
```

## Usage

### Command Line Interface

```bash
# Run all tests and generate vectors
sigma-test
```

### Programmatic Usage

```python
from sigma_protocols.ciphersuite import CIPHERSUITE
from sigma_protocols.sigma_protocols import LinearRelation
from groups import GroupP256
from test_drng import TestDRNG

# Create a discrete logarithm proof
group = GroupP256
rng = TestDRNG(b"my_seed")

# Set up the relation: prove knowledge of x such that X = x * G
relation = LinearRelation(group)
[var_x] = relation.allocate_scalars(1)
[var_G, var_X] = relation.allocate_elements(2)
relation.append_equation(var_X, [(var_x, var_G)])

# Set public values
G = group.generator()
x = group.ScalarField.random(rng)
X = group.scalar_mult(x, G)
relation.set_elements([(var_G, G), (var_X, X)])

# Generate proof using NIZK
nizk = CIPHERSUITE["P256_SHAKE128"]
session_id = b"test_session"
proof = nizk(session_id, relation).prove([x], rng)

# Verify proof
assert nizk(session_id, relation).verify(proof)
```

### Development Commands

```bash
# Run tests
make test
# or
python3 test_sigma_protocols.py

# Generate test vectors
make vectors

# Clean up
make clean
```