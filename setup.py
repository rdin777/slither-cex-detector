from setuptools import setup, find_packages

setup(
    name='slither-cex-detector',
    version='0.3.0',
    packages=find_packages(),
    install_requires=[
        'slither-analyzer',
    ],
    entry_points={
        'slither_detectors': [
            'unprotected-cex-callback = slither_cex_detector.detectors.unprotected_cex_callback:UnprotectedCEXCallback',
        ]
    }
)
