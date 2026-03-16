Quick Start
===========

See the README for full examples.  A minimal workflow::

   from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager
   from tiny_ca.models.certtificate import CAConfig

   mgr = CertLifecycleManager()
   cert_path, key_path = mgr.create_self_signed_ca(
       CAConfig(common_name="My CA", organization="ACME", country="UA",
                key_size=2048, days_valid=3650)
   )
