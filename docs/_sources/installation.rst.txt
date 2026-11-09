Installation
============

.. code-block:: bash

   pip install tiny-ca                  # core, sync
   pip install 'tiny-ca[async]'         # asyncio support
   pip install 'tiny-ca[postgres]'      # PostgreSQL (sync); postgres-async for asyncpg
   pip install 'tiny-ca[mysql]'         # MySQL (sync); mysql-async for aiomysql
   pip install 'tiny-ca[hsm]'           # PKCS#11 / HSM signing (python-pkcs11)
   pip install 'tiny-ca[all]'           # everything

Python 3.11 or newer is required.
