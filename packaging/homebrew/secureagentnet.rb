class Secureagentnet < Formula
  include Language::Python::Virtualenv

  desc "Zero-Trust Security Gateway for Autonomous AI Agents (ITCD Pipeline)"
  homepage "https://github.com/secure-agent-net/secure-agent-net"
  url "https://github.com/secure-agent-net/secure-agent-net/archive/refs/tags/v2.0.0.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256"
  license "MIT"
  version "2.0.0"

  depends_on "python@3.12"

  resource "click" do
    url "https://files.pythonhosted.org/packages/source/c/click/click-8.1.7.tar.gz"
    sha256 "ca9853ad459e787e2192211578cc907e7594e294c7ccc834310722b41b9ca6de"
  end

  resource "rich" do
    url "https://files.pythonhosted.org/packages/source/r/rich/rich-13.7.0.tar.gz"
    sha256 "5cb5123b5cf9ee70584244246816e9114227e0b98ad7496e4e5e5416a5a07f5b"
  end

  resource "pydantic" do
    url "https://files.pythonhosted.org/packages/source/p/pydantic/pydantic-2.5.3.tar.gz"
    sha256 "b3ef57c62535b0941697cce638c08900d87c590c7e917d0a6c7c16aca6b5a2f4"
  end

  resource "pydantic-settings" do
    url "https://files.pythonhosted.org/packages/source/p/pydantic-settings/pydantic_settings-2.1.0.tar.gz"
    sha256 "26b1492e0a86d0ad8b7f3fe1c6ef6f51f148a25eb8310a3a8e84e0da5cdcccf2"
  end

  resource "fastapi" do
    url "https://files.pythonhosted.org/packages/source/f/fastapi/fastapi-0.104.1.tar.gz"
    sha256 "eac15e6b9fe6fac41428c60f2f946cc51fd2d6a3f44a1c4b93059a9e9d40e70a"
  end

  resource "uvicorn" do
    url "https://files.pythonhosted.org/packages/source/u/uvicorn/uvicorn-0.24.0.tar.gz"
    sha256 "368d5f7f2e0e997e7c1b9848acbe9bad0c2e1034a7456c3b8e81aa9a8b85e415"
  end

  resource "SQLAlchemy" do
    url "https://files.pythonhosted.org/packages/source/S/SQLAlchemy/SQLAlchemy-2.0.23.tar.gz"
    sha256 "c1bda93cbbe4b48222c40b1de814aa1897347f573ac7d5557f3eadb4e9f63b18"
  end

  resource "docker" do
    url "https://files.pythonhosted.org/packages/source/d/docker/docker-6.1.3.tar.gz"
    sha256 "565f5dfe4373e6c48dbf0507b982cb0e75e5ef0c8b580ffaa57f4448bec70e9b"
  end

  def install
    virtualenv_install_with_resources

    bin.install_symlink libexec/"bin/secureagentnet"
    bin.install_symlink libexec/"bin/san"

    (etc/"secureagentnet").mkpath
    (var/"lib/secureagentnet/data").mkpath
  end

  def post_install
    ohai "SecureAgentNet installed!"
    ohai ""
    ohai "Quick start:"
    ohai "  export DEPLOY_MODE=local"
    ohai "  secureagentnet doctor"
    ohai "  secureagentnet init --mode local"
    ohai ""
    ohai "For full security features (Docker sandbox, LLM eval):"
    ohai "  brew install docker ollama redis"
    ohai "  export DEPLOY_MODE=docker"
    ohai "  secureagentnet doctor"
  end

  test do
    system bin/"secureagentnet", "version"
    system bin/"secureagentnet", "doctor", "--deploy-mode", "minimal"
  end
end
