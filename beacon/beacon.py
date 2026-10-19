"""
Toy example for a small beacon beacons that
periodically shout a short radio packet.

**From outside:**

- Packet looks like random noise
- No beacon id on the wire
- You cannot tell which device sent it

**For someone who shares a secret with a beacon:**

- Can tell that *their* beacon sent it
- Can reject old packets (replay)
- Missing packets in between do not matter
- Any single packet alone is decrypt-able

**Not required:**

- Shared clocks or timestamps
- Online contact with the beacon
- Public device identifiers in the broadcast
- No Random generator
"""

from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.exceptions import InvalidTag


from typing import Tuple, Optional


# for the packet to look completely random no AD should be set
ASSOCIATED_DATA = None
# for packet format
BYTE_ORDER = "big"
COUNTER_SIZE = 8  # bytes


@dataclass
class Beacon:
    bid: int
    counter: int
    key: bytes

    def increase_counter_by(self, num: int):
        self.counter += num
        return self.counter

    # use beacon ID as nonce
    # uniqueness is the counter in the plain-text
    # thus nonce doesn't need to change per message
    def nonce(self):
        return self.bid.to_bytes(12, BYTE_ORDER)


@dataclass
class Format:
    counter: int

    def encode(self) -> bytes:
        result = self.counter.to_bytes(COUNTER_SIZE, BYTE_ORDER)
        return result

    @classmethod
    def decode(cls, packet: bytes):
        counter = int.from_bytes(packet[:COUNTER_SIZE], BYTE_ORDER)
        return cls(counter=counter)


def send(bkn: Beacon):
    new_counter = bkn.increase_counter_by(1)

    # 8 bytes
    plain_text = Format(counter=new_counter).encode()

    # GCM-SIV encrypts via CTR (stream-like);
    # plain-text can be any length.
    aead = AESGCMSIV(bkn.key)
    # 24 bytes = 8 CT + 16 tag
    cipher_text = aead.encrypt(
        nonce=bkn.nonce(),
        data=plain_text,
        associated_data=ASSOCIATED_DATA,
    )
    return cipher_text


def receive(cipher_text: bytes, beacons: Tuple[Beacon, ...]) -> Optional[Beacon]:
    # the receiver / decoder tries each key
    # the one that decodes is the sender
    for bkn in beacons:
        aead = AESGCMSIV(bkn.key)
        try:
            packet = aead.decrypt(
                nonce=bkn.nonce(),
                data=cipher_text,
                associated_data=ASSOCIATED_DATA,
            )
        except InvalidTag:
            # not our beacon
            continue

        last_counter = bkn.counter
        current_counter = Format.decode(packet).counter
        if current_counter <= last_counter:
            raise ValueError("Replay attack detected!") from None

        missed_packets_count = current_counter - last_counter

        # it's our own beacon
        # receiver should increase its own counter of beacon:
        bkn.increase_counter_by(missed_packets_count)

        return bkn
    return None


if __name__ == "__main__":
    import os
    from random import choice, randint  # only used for example
    from copy import deepcopy

    # example mapping[key: last counter] for each beacon
    # both sides keep track of the last counter
    BEACONS = (
        #      id, counter, key
        Beacon(67, 8642100, os.urandom(16)),
        Beacon(69, 1975300, os.urandom(16)),
        Beacon(85, 1234500, os.urandom(16)),
    )
    MISSED_PACKET_COUNT = randint(0, 9)

    # pick a sender beacon
    # copy it so the counter increase doesn't affect receive
    sender_beacon = deepcopy(choice(BEACONS))

    print("================== pre-shared ==================")
    print("beacon ID   :", sender_beacon.bid)
    print("beacon key  :", sender_beacon.key.hex())
    print("last counter:", sender_beacon.counter)
    print()

    old_counter = sender_beacon.counter

    # miss N sent packets
    for _ in range(MISSED_PACKET_COUNT):
        send(sender_beacon)

    cipher_text = send(sender_beacon)
    sent_counter = sender_beacon.counter
    print("================== ENCRYPT =====================")
    print("old counter :", old_counter)
    print(f"missed {MISSED_PACKET_COUNT} packets")
    print("cur counter :", sent_counter)
    print("plain-text  :", Format(sent_counter).encode().hex(), "=", sent_counter)
    print("              |---counter----|")
    print("              |   8 bytes    |")
    print()

    print("================== PUBLIC  =====================")
    print("cipher-text :", cipher_text.hex(), "(24 bytes)")
    print("              |--cipher-text-||-------------tag--------------|")
    print("              |   8 bytes    ||           16 bytes           |")
    print()

    received_beacon = receive(cipher_text, BEACONS)
    if received_beacon is None:
        raise ValueError("Not one of our beacons") from None

    assert received_beacon.bid == sender_beacon.bid
    assert received_beacon.counter == sender_beacon.counter

    print("================== DECRYPT =====================")
    print("beacon ID   :", received_beacon.bid)
    print("recv counter:", received_beacon.counter)
    print("plain-text  :", Format(received_beacon.counter).encode().hex(), "=", received_beacon.counter)
    print("              |---counter----|")
    print("              |   8 bytes    |")
    print()
