import setuptools

with open("README.rst", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="nessus_file_reader",
    version="0.3.0",
    author="Damian Krawczyk",
    author_email="damian.krawczyk@limberduck.org",
    description="nessus file reader by LimberDuck (pronounced *ˈlɪm.bɚ dʌk*) is a python module "
                "created to quickly parse nessus files containing the results of scans "
                "performed by using Nessus by (C) Tenable, Inc.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/LimberDuck/nessus-file-reader",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
    ],
)
