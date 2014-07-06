Feature: Ability to mint while the coins are in cold storage
  The feature was described and discussed here: http://www.peercointalk.org/index.php?topic=2783.0

  Scenario: An user mints with a minting only key and later spends the funds with the spending key
    Given a network with node "Alice" able to mint
    And a node "Bob" with an empty wallet
    And node "Bob" generates a new address "bob"
    And node "Alice" sends "10,000.01" to "bob"
    And node "Alice" finds a block
    And node "Bob" reaches a balance of "10,000.01"

    Given a node "Cold storage" with an empty wallet
    And node "Cold storage" generates a new address "cold storage"

    When node "Bob" generates a new address "minting"
    And node "Bob" generates a new cold minting address "cold minting" with the minting address "minting" and the spending address "cold storage"

    And node "Bob" sends "10,000" to "cold minting"
    And all nodes reach 1 transaction in memory pool
    And node "Alice" finds a block received by all other nodes

    Then node "Bob" should have a balance of "0"
    And node "Bob" should have a minting only balance of "10,000"

    When node "Alice" finds blocks until just received coins are able to mint
    And all nodes are after the protocol V05 switch time
    Then node "Bob" should be able to find a block "X"
    And all nodes should reach block "X"
    And node "Bob" should have a stake of "10,000" + the reward on block "X"
    And node "Bob" should have a minting only balance of "0"
    And node "Bob" should have a balance of "0"

    When node "Alice" finds enough blocks for a Proof of Stake block to mature
    And all nodes reach the same height
    Then node "Bob" should have a stake of "0"
    And node "Bob" should have a minting only balance of "10,000" + the reward on block "X"
    And node "Bob" should have a balance of "0"

    When node "Cold storage" dumps the private key of "cold storage"
    And node "Bob" imports the private key of "cold storage"
    Then node "Bob" should have a minting only balance of "0"
    And node "Bob" should have a balance of "10,000" + the reward on block "X"

    When node "Alice" generates a new address "alice"
    And node "Bob" sends "10" to "alice"
    And all nodes reach 1 transaction in memory pool
    And node "Alice" finds a block received by all other nodes
    Then node "Bob" should have a balance of "9,989.99" + the reward on block "X"

  Scenario: Cold minting before switch time
    Given a network with node "Alice" able to mint
    And a node "Bob" with an empty wallet
    And a node "Cold storage" with an empty wallet
    And node "Cold storage" generates a new address "cold storage"
    And node "Bob" generates a new address "minting"
    And node "Bob" generates a new cold minting address "cold minting" with the minting address "minting" and the spending address "cold storage"
    And node "Alice" sends "10,000" to "cold minting"
    And node "Alice" finds blocks until just received coins are able to mint
    Then node "Bob" should not be able to find a block "X"

  Scenario: Cold minting with cold minted coins
    Given a network with node "Alice" able to mint
    And a node "Bob" with an empty wallet
    And a node "Cold storage" with an empty wallet
    And node "Cold storage" generates a new address "cold storage"
    And node "Bob" generates a new address "minting"
    And node "Bob" generates a new cold minting address "cold minting" with the minting address "minting" and the spending address "cold storage"
    And node "Alice" sends "10,000" to "cold minting"
    And node "Alice" finds blocks until just received coins are able to mint
    And all nodes are after the protocol V05 switch time
    When node "Bob" finds a block received by all other nodes
    And node "Alice" finds enough blocks for a Proof of Stake block to mint again
    And all nodes reach the same height
    Then node "Bob" should be able to find a block "Y"
    And all nodes should reach block "Y"
