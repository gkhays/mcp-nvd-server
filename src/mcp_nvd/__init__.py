from . import server
import asyncio

def main():
    """Main function to run the server."""
    asyncio.run(server.main())

__all__ = ['main', 'server']