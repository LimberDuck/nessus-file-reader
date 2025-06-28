import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt") as f:
    required = f.read().splitlines()

about = {}
with open("nessus_file_reader/_version.py") as f:
    exec(f.read(), about)

setuptools.setup(
    name="nessus_file_reader",
    version=about["__version__"],
    license="GPLv3",
    author="Damian Krawczyk",
    author_email="damian.krawczyk@limberduck.org",
    description="nessus file reader (NFR) by LimberDuck is a CLI tool and python module "
    "created to quickly parse nessus files containing the results of scans "
    "performed by using Nessus by (C) Tenable, Inc.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/LimberDuck/nessus-file-reader",
    packages=setuptools.find_packages(),
    install_requires=required,
    entry_points={"console_scripts": ["nfr = nessus_file_reader.__main__:main"]},
    classifiers=[
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
    ],
)
