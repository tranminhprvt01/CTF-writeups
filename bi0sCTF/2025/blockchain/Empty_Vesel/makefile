export RPC_URL=http://rpc.eng.run:8570
export PRIVATE_KEY=0xa5ebe506fef8553c9133e8dbef7ff3994cd2490f37d8ba8c0d43cb77d423d82e

deploy:
	rm -rf ./broadcast/* &&\
	forge script script/Deploy.s.sol:Deploy --rpc-url $(RPC_URL)  --private-key $(PRIVATE_KEY) --broadcast -vvvv

