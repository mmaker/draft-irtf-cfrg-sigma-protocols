"""Setup script for sigma-protocols-py package."""

from setuptools import setup, find_packages

setup(
    name="sigma-protocols-py",
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    packages=find_packages(),
    include_package_data=True,
)