// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

// Compiles the canonical Permit2 with its own pinned compiler so tests and
// scripts can deploy it with deployCode("Permit2.sol:Permit2").
import {Permit2} from "permit2/src/Permit2.sol";
