pragma solidity >=0.6.0;

contract CellhashCalc {

	/// @dev Method that computes the representation hash of the cell (i.e. containing code), useful for Ton Labs' SetcodeMultisigWallet's submitUpdate function
	/// @param c Cell, representation hash for which is to be computed 
	/// @return codeHash Representation hash of the passed cell
	function calcCellHash(TvmCell c) public pure
		returns (uint256 codeHash)
	{
		codeHash = tvm.hash(c);
	}

}