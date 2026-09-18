//! EVM function-selector lookup (offline knowledge, not a chain query).
//!
//! First 4 bytes of keccak256("name(types)") as seen in transaction calldata
//! and traces. Curated set of widely-deployed selectors (ERC20/721, proxies,
//! Uniswap V2, WETH, Gnosis Safe). Unknown selectors report as unknown.

pub struct EvmSelector {
    pub selector: &'static str,
    pub signature: &'static str,
    pub area: &'static str,
}

pub const EVM_SELECTORS: &[EvmSelector] = &[
    // ERC20
    sel("a9059cbb", "transfer(address,uint256)", "ERC20"),
    sel("095ea7b3", "approve(address,uint256)", "ERC20"),
    sel("23b872dd", "transferFrom(address,address,uint256)", "ERC20"),
    sel("70a08231", "balanceOf(address)", "ERC20"),
    sel("18160ddd", "totalSupply()", "ERC20"),
    sel("dd62ed3e", "allowance(address,address)", "ERC20"),
    sel("06fdde03", "name()", "ERC20"),
    sel("95d89b41", "symbol()", "ERC20"),
    sel("313ce567", "decimals()", "ERC20"),
    // ERC721
    sel("42842e0e", "safeTransferFrom(address,address,uint256)", "ERC721"),
    sel("b88d4fde", "safeTransferFrom(address,address,uint256,bytes)", "ERC721"),
    sel("a22cb465", "setApprovalForAll(address,bool)", "ERC721"),
    sel("081812fc", "getApproved(uint256)", "ERC721"),
    sel("e985e9c5", "isApprovedForAll(address,address)", "ERC721"),
    sel("6352211e", "ownerOf(uint256)", "ERC721"),
    sel("01ffc9a7", "supportsInterface(bytes4)", "ERC165"),
    sel("150b7a02", "onERC721Received(address,address,uint256,bytes)", "ERC721"),
    // Ownership / pausable
    sel("8da5cb5b", "owner()", "Ownable"),
    sel("f2fde38b", "transferOwnership(address)", "Ownable"),
    sel("715018a6", "renounceOwnership()", "Ownable"),
    sel("5c975abb", "paused()", "Pausable"),
    sel("8456cb59", "pause()", "Pausable"),
    sel("3f4ba83a", "unpause()", "Pausable"),
    // WETH
    sel("d0e30db0", "deposit()", "WETH"),
    sel("2e1a7d4d", "withdraw(uint256)", "WETH"),
    // Uniswap V2 router
    sel("7ff36ab5", "swapExactETHForTokens(uint256,address[],address,uint256)", "UniswapV2"),
    sel("18cbafe5", "swapExactTokensForETH(uint256,uint256,address[],address,uint256)", "UniswapV2"),
    sel("38ed1739", "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)", "UniswapV2"),
    sel("8803dbee", "swapTokensForExactTokens(uint256,uint256,address[],address,uint256)", "UniswapV2"),
    sel("fb3bdb41", "swapETHForExactTokens(uint256,address[],address,uint256)", "UniswapV2"),
    sel("f305d719", "addLiquidityETH(address,uint256,uint256,uint256,address,uint256)", "UniswapV2"),
    sel("e8e33700", "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)", "UniswapV2"),
    sel("02751cec", "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)", "UniswapV2"),
    sel("baa2abde", "removeLiquidityETH(address,uint256,uint256,uint256,address,uint256)", "UniswapV2"),
    sel("2195995c", "WETH()", "UniswapV2"),
    sel("ad5c4648", "getAmountsOut(uint256,address[])", "UniswapV2"),
    // Proxies
    sel("5c60da1b", "implementation()", "Proxy"),
    sel("3659cfe6", "upgradeTo(address)", "Proxy"),
    sel("4f1ef286", "upgradeToAndCall(address,bytes)", "Proxy"),
    sel("f851a440", "admin()", "TransparentProxy"),
    sel("8f283970", "_implementation()", "TransparentProxy"),
    sel("1f931c1c", "diamondCut((address,uint8,bytes4[])[],address,bytes)", "Diamond"),
    sel("52ef6b2c", "facetAddresses()", "Diamond"),
    // Gnosis Safe
    sel("6a761202", "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)", "Safe"),
    sel("a97ab18a", "setup(address[],uint256,address,bytes,address,address,uint256,address)", "Safe"),
    // Common misc
    sel("3ccfd60b", "withdraw()", "Common"),
    sel("4e71d92d", "claim(uint256,address,uint256,bytes32[])", "MerkleDistributor"),
];

const fn sel(selector: &'static str, signature: &'static str, area: &'static str) -> EvmSelector {
    EvmSelector { selector, signature, area }
}

/// Look up a 4-byte selector. Accepts "a9059cbb", "0xa9059cbb", pasted calldata.
pub fn lookup_evm_selector(input: &str) -> Option<&'static EvmSelector> {
    let stripped = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    let hex: String = stripped
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() < 8 {
        return None;
    }
    let selector = &hex[..8];
    EVM_SELECTORS.iter().find(|s| s.selector == selector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_selectors_resolve() {
        assert_eq!(lookup_evm_selector("a9059cbb").unwrap().area, "ERC20");
        assert_eq!(
            lookup_evm_selector("0x23b872dd").unwrap().signature,
            "transferFrom(address,address,uint256)"
        );
        assert_eq!(lookup_evm_selector("1f931c1c").unwrap().area, "Diamond");
    }

    #[test]
    fn calldata_prefix_and_unknown() {
        // Full calldata: selector is the first 4 bytes.
        assert_eq!(
            lookup_evm_selector("0xa9059cbb0000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d").unwrap().area,
            "ERC20"
        );
        assert!(lookup_evm_selector("deadbeef").is_none());
        assert!(lookup_evm_selector("abc").is_none());
    }
}
