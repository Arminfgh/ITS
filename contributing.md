Contributing to SecureOffice Hub
First off, thank you for considering contributing to SecureOffice Hub! 🎉

📋 Table of Contents
Code of Conduct
How Can I Contribute?
Development Setup
Coding Standards
Testing
Pull Request Process
🤝 Code of Conduct
This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

🚀 How Can I Contribute?
Reporting Bugs
Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

Use a clear and descriptive title
Describe the exact steps which reproduce the problem
Provide specific examples to demonstrate the steps
Describe the behavior you observed after following the steps
Explain which behavior you expected to see instead and why
Include screenshots if possible
Suggesting Enhancements
Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

Use a clear and descriptive title
Provide a step-by-step description of the suggested enhancement
Provide specific examples to demonstrate the steps
Describe the current behavior and explain which behavior you expected to see instead
Explain why this enhancement would be useful
Pull Requests
Fill in the required template
Do not include issue numbers in the PR title
Follow the coding standards
Include appropriate test cases
Update documentation as needed
End all files with a newline
💻 Development Setup
Fork the repository
bash
git clone https://github.com/yourusername/secureoffice-hub.git
cd secureoffice-hub
Create virtual environment
bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows
Install dependencies
bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
Install pre-commit hooks
bash
pre-commit install
Create .env file
bash
cp .env.example .env
# Edit .env with your settings
📝 Coding Standards
Python Style Guide
We follow PEP 8 with some modifications:

Line length: 120 characters (not 79)
Use black for auto-formatting
Use isort for import sorting
Use type hints where possible
Code Formatting
Before committing, run:

bash
# Format code
black .
isort .

# Check style
flake8 .
pylint src/
Documentation
All public functions must have docstrings
Use Google-style docstrings
Update README.md if adding new features
Add comments for complex logic
Example docstring:

python
def scan_network(network_range: str, ports: List[int]) -> Dict:
    """
    Scans a network range for open ports.
    
    Args:
        network_range: IP range in CIDR notation (e.g., "192.168.1.0/24")
        ports: List of ports to scan
        
    Returns:
        Dictionary containing scan results with host information
        
    Raises:
        ValueError: If network_range is invalid
        ConnectionError: If network is unreachable
    """
    pass
🧪 Testing
Running Tests
bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=. --cov-report=html

# Specific test file
pytest tests/test_scanner.py -v

# Specific test
pytest tests/test_scanner.py::test_localhost_scan -v
Writing Tests
Place tests in tests/ directory
Name test files test_*.py
Name test functions test_*
Use descriptive test names
Aim for >80% code coverage
Example test:

python
def test_port_scanner_finds_open_port():
    """Test that port scanner correctly identifies open ports"""
    scanner = PortScanner()
    result = scanner.scan_port("127.0.0.1", 80)
    assert result.is_open == True
    assert result.service == "HTTP"
📤 Pull Request Process
Create a feature branch
bash
git checkout -b feature/amazing-feature
Make your changes
Write clear, concise commit messages
Follow the coding standards
Add tests for new functionality
Update documentation
Run tests and checks
bash
pytest tests/ -v
black .
isort .
flake8 .
Push to your fork
bash
git push origin feature/amazing-feature
Open a Pull Request
Use a clear and descriptive title
Reference any related issues
Describe your changes in detail
Include screenshots for UI changes
Wait for code review
Pull Request Checklist
 Code follows the style guidelines
 Self-review of code completed
 Comments added for complex code
 Documentation updated
 Tests added and passing
 No new warnings generated
 Dependent changes merged
 Screenshots included (if applicable)
🏷️ Git Commit Messages
Use the present tense ("Add feature" not "Added feature")
Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
Limit the first line to 72 characters or less
Reference issues and pull requests liberally after the first line
Example:

Add threat intelligence integration

- Integrate AlienVault OTX API
- Add Abuse.ch URLhaus support
- Update documentation

Closes #123
🎯 Development Workflow
Pick an issue or create one
Comment that you're working on it
Fork and create a branch
Make your changes
Write/update tests
Update documentation
Submit pull request
Address review comments
Merge!
📞 Questions?
Feel free to:

Open an issue
Contact the maintainers
Join our discussions
🙏 Thank You!
Your contributions make SecureOffice Hub better for everyone!

Remember: Quality over quantity. A well-tested, documented, small contribution is better than a large, untested one.

