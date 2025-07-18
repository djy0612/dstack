import pytest
from solders.keypair import Keypair

from dstack_sdk import AsyncDstackClient, GetKeyResponse
from dstack_sdk.solana import to_keypair

@pytest.mark.asyncio
async def test_async_to_keypair():
    client = AsyncDstackClient()
    result = await client.get_key('test')
    assert isinstance(result, GetKeyResponse)
    keypair = to_keypair(result)
    assert isinstance(keypair, Keypair)