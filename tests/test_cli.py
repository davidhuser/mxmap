from unittest.mock import AsyncMock, patch

from mail_sovereignty.cli import postprocess, preprocess, validate


class TestCli:
    def test_preprocess(self):
        with patch("mail_sovereignty.preprocess.run", new_callable=AsyncMock) as mock_run:
            preprocess()
            mock_run.assert_called_once()

    def test_postprocess(self):
        with patch("mail_sovereignty.postprocess.run", new_callable=AsyncMock) as mock_run:
            postprocess()
            mock_run.assert_called_once()

    def test_validate(self):
        with patch("mail_sovereignty.validate.run") as mock_run:
            validate()
            mock_run.assert_called_once()
