from pathlib import Path


def profile_application(app_path):
    app_path = Path(app_path)

    profile = {
        "application": app_path.name,
        "path": str(app_path),
        "languages": [],
        "manifests": [],
        "files": []
    }

    # Collect files
    for file in app_path.rglob("*"):
        if file.is_file():
            profile["files"].append(str(file.relative_to(app_path)))

    # Detect Python
    if (
        (app_path / "requirements.txt").exists()
        or list(app_path.rglob("*.py"))
    ):
        profile["languages"].append("python")

    if (app_path / "requirements.txt").exists():
        profile["manifests"].append("requirements.txt")

    # Detect Node.js
    if (app_path / "package.json").exists():
        profile["languages"].append("javascript")
        profile["manifests"].append("package.json")

    # Detect Java
    if (app_path / "pom.xml").exists():
        profile["languages"].append("java")
        profile["manifests"].append("pom.xml")

    # Detect Go
    if (app_path / "go.mod").exists():
        profile["languages"].append("go")
        profile["manifests"].append("go.mod")

    # Detect Docker
    if (app_path / "Dockerfile").exists():
        profile["manifests"].append("Dockerfile")

    return profile