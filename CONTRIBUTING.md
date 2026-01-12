# Contributing to Red Team Automation Framework

Thank you for your interest in contributing! This document provides guidelines for contributing to this educational security project.

## Code of Conduct

### Our Commitment

This project is for **educational and authorized security testing only**. All contributors must:

- Never encourage or assist in unauthorized access
- Follow responsible disclosure practices
- Respect privacy and handle security information responsibly
- Comply with all applicable laws and regulations

## How to Contribute

### Reporting Bugs

If you find a bug:

1. Check if it's already reported in Issues
2. If not, create a new issue with:
   - Clear description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - Your environment (OS, Python version)

### Suggesting Enhancements

We welcome enhancement suggestions:

1. Check existing issues and pull requests
2. Create an issue describing:
   - The enhancement
   - Why it's useful
   - Potential implementation approach

### Pull Requests

1. **Fork the repository**
2. **Clone and setup development environment**
   ```bash
   git clone https://github.com/YOUR-USERNAME/Red-Team-Automation-Tool-.git
   cd Red-Team-Automation-Tool-
   
   # Create and activate virtual environment
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install dependencies
   pip install -r requirements.txt
   ```

3. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make your changes**
   - Follow existing code style
   - Add comments for complex logic
   - Update documentation if needed

5. **Test your changes**
   - Ensure code runs without errors
   - Test with different targets if applicable

6. **Commit your changes**
   ```bash
   git commit -m "Add feature: description"
   ```

7. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

8. **Create a Pull Request**
   - Provide clear description
   - Link to any related issues
   - Explain what you changed and why

## Development Guidelines

### Code Style

- Follow PEP 8 Python style guide
- Use meaningful variable and function names
- Add docstrings to classes and functions
- Keep functions focused and small

### Documentation

- Update README.md if adding features
- Add docstrings to new functions
- Include usage examples for new modules
- Update configuration examples if needed

### Testing

- Test on safe, authorized targets only
- Verify no breaking changes
- Test with different Python versions if possible

### Security Considerations

- Never include real credentials or API keys
- No actual exploits - proof-of-exposure only
- Validate user input
- Handle errors gracefully

## Project Structure

```
Red-Team-Automation-Tool/
├── core/           # Core framework (orchestrator, config, models)
├── modules/        # Functional modules (recon, scan, enum, vuln, mitre)
├── reporting/      # Report generation
├── utils/          # Utilities (banner, helpers)
├── config.yaml     # Configuration
├── main.py         # CLI entry point
└── tests/          # Tests (future)
```

## Module Development

### Creating a New Module

1. Create directory under `modules/`
2. Add `__init__.py`
3. Implement your module class
4. Follow existing module patterns
5. Update orchestrator if needed
6. Document usage in README

### Example Module Structure

```python
"""
Module Description
"""
from core.logger import Logger
from core.config import get_config

class YourModule:
    """Your module class"""
    
    def __init__(self):
        """Initialize module"""
        self.logger = Logger.get(__name__)
        self.config = get_config()
    
    def execute(self, target: str):
        """Execute module functionality"""
        self.logger.info(f"Running module on {target}")
        # Implementation
        return results
```

## Recognition

Contributors will be:
- Listed in project acknowledgments
- Credited in commit history
- Mentioned in release notes

## Questions?

- Open an issue for questions
- Check existing documentation
- Review code examples in the project

## License

By contributing, you agree that your contributions will be part of this educational project.

---

Thank you for helping make this project better! 🙏
