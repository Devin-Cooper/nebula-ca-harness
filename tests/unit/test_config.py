import unittest

from causb import config


class TestConfig(unittest.TestCase):
    def test_constants_present(self):
        assert config.BOX_NAME == "nebula-ca"
        assert config.NS == "nebula-ca-job"
        assert config.CAPS["jobs"] == 1
        assert config.CA_DIR.endswith("/ca")
        assert config.BACKUP_RECIPIENT == "/etc/nebula-ca/backup-recipient.age"
        assert config.JOB_USER == "nebula-job"
        assert config.HANDLERS_DIR == "/usr/local/lib/ca-usb/handlers"
        assert config.AUDIT_LOG == "/var/lib/nebula-ca/audit.log"


if __name__ == "__main__":
    unittest.main()
