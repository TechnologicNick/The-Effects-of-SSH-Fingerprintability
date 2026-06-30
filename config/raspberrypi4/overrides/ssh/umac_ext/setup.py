from setuptools import Extension, setup


setup(
    name="openssh_umac",
    version="0.1.0",
    ext_modules=[
        Extension(
            "openssh_umac",
            sources=[
                "openssh_umac_module.c",
                "umac.c",
                "umac128.c",
            ],
            include_dirs=["."],
            libraries=["crypto"],
        )
    ],
)
