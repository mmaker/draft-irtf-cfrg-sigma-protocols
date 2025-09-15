"""
Pure Python implementation of Sigma protocols for zero-knowledge proofs.
"""

from abc import ABC, abstractmethod
from collections import namedtuple


class SigmaProtocol(ABC):
    """
    Abstract base class for Sigma protocols.

    A Sigma protocol is a 3-message protocol that is special sound and
    honest-verifier zero-knowledge.
    """

    @abstractmethod
    def __init__(self, instance):
        raise NotImplementedError

    @abstractmethod
    def prover_commit(self, witness, rng):
        raise NotImplementedError

    @abstractmethod
    def prover_response(self, prover_state, challenge):
        raise NotImplementedError

    @abstractmethod
    def verifier(self, commitment, challenge, response):
        raise NotImplementedError

    @abstractmethod
    def serialize_commitment(self, commitment):
        raise NotImplementedError

    @abstractmethod
    def serialize_response(self, response):
        raise NotImplementedError

    @abstractmethod
    def deserialize_commitment(self, data):
        raise NotImplementedError

    @abstractmethod
    def deserialize_response(self, data):
        raise NotImplementedError

    def simulate_response(self, rng):
        raise NotImplementedError

    def simulate_commitment(self, response, challenge):
        raise NotImplementedError


class SchnorrProof(SigmaProtocol):
    """
    Sigma protocol for linear relations (Schnorr-type proofs).
    """

    ProverState = namedtuple("ProverState", ["witness", "nonces"])

    def __init__(self, instance):
        self.instance = instance

    def prover_commit(self, witness, rng):
        """Generate prover's first message (commitment)."""
        nonces = [
            self.instance.Domain.random(rng)
            for _ in range(self.instance.linear_map.num_scalars)
        ]
        prover_state = self.ProverState(witness, nonces)
        commitment = self.instance.linear_map(nonces)
        return (prover_state, commitment)

    def prover_response(self, prover_state, challenge):
        """Generate prover's response to challenge."""
        witness, nonces = prover_state
        response = []
        for i in range(self.instance.linear_map.num_scalars):
            # response[i] = nonce[i] + witness[i] * challenge
            resp = nonces[i] + witness[i] * challenge
            response.append(resp)

        return response

    def verifier(self, commitment, challenge, response):
        """Verify the proof."""
        assert len(commitment) == self.instance.linear_map.num_constraints
        assert len(response) == self.instance.linear_map.num_scalars

        expected = self.instance.linear_map(response)

        got = []
        for i in range(self.instance.linear_map.num_constraints):
            # got[i] = commitment[i] + instance.image[i] * challenge
            result = commitment[i] + self.instance.image[i] * challenge
            got.append(result)

        # Verify the proof
        assert got == expected, f"Verification failed: {got} != {expected}"
        return True

    def serialize_commitment(self, commitment):
        return self.instance.Image.serialize(commitment)

    def serialize_challenge(self, challenge):
        return self.instance.Domain.serialize([challenge])

    def serialize_response(self, response):
        return self.instance.Domain.serialize(response)

    def deserialize_commitment(self, data):
        return self.instance.Image.deserialize(data)

    def deserialize_challenge(self, data):
        scalar_size = self.instance.Domain.scalar_byte_length()
        return self.instance.Domain.deserialize(data[:scalar_size])[0]

    def deserialize_response(self, data):
        return self.instance.Domain.deserialize(data)

    def simulate_response(self, rng):
        """Simulate a random response (for zero-knowledge property)."""
        return [
            self.instance.Domain.random(rng)
            for _ in range(self.instance.linear_map.num_scalars)
        ]

    def simulate_commitment(self, response, challenge):
        """Simulate commitment given response and challenge."""
        h_c_values = [
            self.instance.image[i] * challenge
            for i in range(self.instance.linear_map.num_constraints)
        ]
        return [
            self.instance.linear_map(response)[i] - h_c_values[i]
            for i in range(self.instance.linear_map.num_constraints)
        ]

    def get_instance_label(self):
        return self.instance.get_label()

    @staticmethod
    def get_protocol_id():
        """Returns a 64-byte unique identifier for this protocol."""
        return b'ietf sigma proof linear relation' + b'\0' * 31


class LinearMap:
    """
    Linear morphism for Sigma protocols.
    Implements sparse matrix-vector multiplication.
    """

    LinearCombination = namedtuple("LinearCombination", ["scalar_indices", "element_indices"])

    def __init__(self, group):
        self.linear_combinations = []
        self.group_elements = []
        self.group = group
        self.num_scalars = 0
        self.num_elements = 0
        self.num_constraints = 0

    def __call__(self, scalars):
        """Apply the linear map to scalars."""
        results = []
        for lc in self.linear_combinations:
            result = self.group.identity()
            for scalar_idx, element_idx in zip(lc.scalar_indices, lc.element_indices):
                scalar = scalars[scalar_idx]
                element = self.group_elements[element_idx]
                result = result + element * scalar
            results.append(result)
        return results

    def add_constraint(self, scalar_indices, element_indices):
        """Add a linear constraint."""
        lc = self.LinearCombination(scalar_indices, element_indices)
        self.linear_combinations.append(lc)
        self.num_constraints += 1

    def set_elements(self, elements):
        """Set the group elements for the linear map."""
        self.group_elements = elements
        self.num_elements = len(elements)


class LinearRelation:
    """
    Represents a linear relation for Sigma protocols.
    """

    def __init__(self, group):
        self.group = group
        self.Domain = group.ScalarField
        self.Image = group
        self.linear_map = LinearMap(group)

        self.scalar_vars = []
        self.element_vars = []
        self.element_values = {}
        self.equations = []

        self._next_scalar_id = 0
        self._next_element_id = 0

    def allocate_scalars(self, count):
        """Allocate scalar variables."""
        vars = []
        for _ in range(count):
            var_id = self._next_scalar_id
            self._next_scalar_id += 1
            vars.append(var_id)
            self.scalar_vars.append(var_id)
        self.linear_map.num_scalars = len(self.scalar_vars)
        return vars

    def allocate_elements(self, count):
        """Allocate element variables."""
        vars = []
        for _ in range(count):
            var_id = self._next_element_id
            self._next_element_id += 1
            vars.append(var_id)
            self.element_vars.append(var_id)
        return vars

    def set_elements(self, assignments):
        """Set values for element variables."""
        for var_id, value in assignments:
            self.element_values[var_id] = value

        # Update the linear map's group elements
        elements = []
        for var_id in self.element_vars:
            if var_id in self.element_values:
                elements.append(self.element_values[var_id])
        self.linear_map.set_elements(elements)

    def append_equation(self, lhs_element, rhs_terms):
        """
        Add an equation: lhs_element = sum(scalar * element for scalar, element in rhs_terms)
        """
        self.equations.append((lhs_element, rhs_terms))

        # Convert to linear map constraint
        scalar_indices = []
        element_indices = []

        for scalar_var, element_var in rhs_terms:
            scalar_idx = self.scalar_vars.index(scalar_var)
            element_idx = self.element_vars.index(element_var)
            scalar_indices.append(scalar_idx)
            element_indices.append(element_idx)

        self.linear_map.add_constraint(scalar_indices, element_indices)

    @property
    def image(self):
        """Get the image elements (LHS of equations)."""
        result = []
        for lhs_element, _ in self.equations:
            result.append(self.element_values[lhs_element])
        return result

    def linear_map(self, scalars):
        """Apply the linear map."""
        return self.linear_map(scalars)

    def get_label(self):
        """Get a label describing this relation."""
        # Serialize the structure of the relation
        import hashlib
        h = hashlib.sha256()

        # Include number of scalars and elements
        h.update(self.linear_map.num_scalars.to_bytes(4, 'little'))
        h.update(self.linear_map.num_elements.to_bytes(4, 'little'))
        h.update(self.linear_map.num_constraints.to_bytes(4, 'little'))

        # Include the actual elements
        for element in self.linear_map.group_elements:
            h.update(self.group.serialize([element]))

        # Include the image elements
        for element in self.image:
            h.update(self.group.serialize([element]))

        return h.digest()


class Instance:
    """
    A pair (linear_map, image) for which there exists a witness such that linear_map(witness) = image.
    """

    def __init__(self, group, linear_map, image):
        self.Domain = group.ScalarField
        self.Image = group
        self.linear_map = linear_map
        self.image = image

    def get_label(self):
        """Get instance label."""
        import hashlib
        h = hashlib.sha256()

        # Include linear map structure
        h.update(self.linear_map.num_scalars.to_bytes(4, 'little'))
        h.update(self.linear_map.num_constraints.to_bytes(4, 'little'))

        # Include image elements
        for element in self.image:
            h.update(self.Image.serialize([element]))

        return h.digest()