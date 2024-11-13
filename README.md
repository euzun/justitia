# Justitia

A Python implementation of Justitia: Cryptographic key derivation from biometric inferences for remote authentication.

## Overview

Justitia provides cryptographic key derivation and fuzzy extractor functions optimized for biometric data. It includes the generation of Locality Sensitive Hash (LSH) for feature arrays, as well as error-tolerant key generation from biometric inferences using secure masking techniques.

### Reference

If you use Justitia in your research, please cite the following paper:

> Erkam Uzun, Carter Yagemann, Simon Chung, Vladimir Kolesnikov, and Wenke Lee. 2021. Cryptographic Key Derivation from Biometric Inferences for Remote Authentication. In Proceedings of the 2021 ACM Asia Conference on Computer and Communications Security (ASIA CCS '21). Association for Computing Machinery, New York, NY, USA, 629–643. https://doi.org/10.1145/3433210.3437512

## Requirements

To run this project, you'll need to have Python 3.8+ installed.

### Dependencies

Install the necessary dependencies using the `requirements.txt` file:

```plaintext
fastpbkdf2==0.2.0
numpy==1.22.4
scikit-learn==1.0.2
scipy==1.8.1
```

## Installation

1. **Clone the repository:**
```bash
git clone https://github.com/euzun/justitia.git
cd justitia
```
2. **Install dependencies:**
To set up the environment and install all necessary packages, run the following command:
```bash
pip install -r requirements.txt
```

## Installing Specific Requirements

* `fastpbkdf2` is used for fast PBKDF2-HMAC key derivation.
* `numpy` and `scipy` are used for array manipulation, random sampling, and statistical analysis.
* `scikit-learn` is required for normalization operations on hyperplanes in LSH generation.

## Usage

Once installed, you can use Justitia by executing the main Python script with the required arguments:

```bash
python justitia.py EMB_DIR ENR_ID QUE_ID LSH_BIT_LEN MASK_PROB NROF_SUB_BITS FE_ERR_THR
```

Where:

* `EMB_DIR:` Path to the embeddings directory.
* `ENR_ID:` Index of the enrollment person (embedding label).
* `QUE_ID:` Index of the query person (embedding label).
* `LSH_BIT_LEN:` Length of LSH in bits.
* `MASK_PROB:` Noise cancellation masking probability.
* `NROF_SUB_BITS:` Number of bits subsampled in the fuzzy extractor.
* `FE_ERR_THR:` Number of error bits the fuzzy extractor can tolerate.

## Example
```bash
python justitia.py /path/to/embeddings 1 2 128 0.1 8 2
```

This command will run the biometric key derivation for the enrollment ID 1 and query ID 2 using embeddings located in `/path/to/embeddings`, with the specified parameters for LSH bit length, masking probability, number of bits for subsampling, and fuzzy extractor error threshold.