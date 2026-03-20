class Agentguard < Formula
  include Language::Python::Virtualenv

  desc "Runtime detection and response for AI agents"
  homepage "https://github.com/An33shh/AgentGuard"
  url "https://files.pythonhosted.org/packages/source/a/agentguard/agentguard-0.9.0.tar.gz"
  # Update sha256 after publishing to PyPI:
  #   curl -sL <url> | shasum -a 256
  sha256 "PLACEHOLDER_UPDATE_AFTER_PYPI_PUBLISH"
  license "MIT"

  depends_on "python@3.12"

  # Core dependencies — generated from: pip install agentguard[all] && pip freeze
  # Regenerate with: brew update-python-resources agentguard
  resource "anthropic" do
    url "https://files.pythonhosted.org/packages/source/a/anthropic/anthropic-0.40.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "fastapi" do
    url "https://files.pythonhosted.org/packages/source/f/fastapi/fastapi-0.115.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "uvicorn" do
    url "https://files.pythonhosted.org/packages/source/u/uvicorn/uvicorn-0.32.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "pydantic" do
    url "https://files.pythonhosted.org/packages/source/p/pydantic/pydantic-2.10.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "pydantic-settings" do
    url "https://files.pythonhosted.org/packages/source/p/pydantic_settings/pydantic_settings-2.6.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "sqlalchemy" do
    url "https://files.pythonhosted.org/packages/source/S/SQLAlchemy/SQLAlchemy-2.0.36.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "aiosqlite" do
    url "https://files.pythonhosted.org/packages/source/a/aiosqlite/aiosqlite-0.20.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "structlog" do
    url "https://files.pythonhosted.org/packages/source/s/structlog/structlog-24.4.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "pyyaml" do
    url "https://files.pythonhosted.org/packages/source/P/PyYAML/PyYAML-6.0.2.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "pyjwt" do
    url "https://files.pythonhosted.org/packages/source/P/PyJWT/PyJWT-2.8.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "python-dotenv" do
    url "https://files.pythonhosted.org/packages/source/p/python_dotenv/python_dotenv-1.0.1.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "httpx" do
    url "https://files.pythonhosted.org/packages/source/h/httpx/httpx-0.27.2.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "redis" do
    url "https://files.pythonhosted.org/packages/source/r/redis/redis-5.0.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "AgentGuard", shell_output("#{bin}/agentguard --help")
  end
end
