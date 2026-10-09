"""Corpus staging for tinyforge.

Layout (gitignored, populated by the Stage 1 pipeline):

    data/raw/          downloaded dataset files, unmodified
    data/processed/    normalized SFT rows

Every processed row must carry provenance — source dataset, source row ID,
and license. Without that, the copy-rate metric cannot distinguish
memorisation from generalisation.
"""
