# Justitia

A Python implementation of Justitia: Cryptographic key derivation from biometric inferences for remote authentication.

## Overview

Justitia provides cryptographic key derivation from biometric data, enabling the secure locking and unlocking of a chosen secret (e.g., the private key of a (public, private) key pair) while storing it in a remote database without revealing any biometric data to third parties. Justitia combines the accuracy of state-of-the-art deep learning (DL) models in biometric verification with zero-knowledge-proof (ZKP)-based cryptographic schemes. It introduces sophisticated techniques to transform the fuzzy domain of DL embeddings into a cryptographically compatible Hamming space, using powerful noise-suppressing methods. Please refer our paper for more details.

### Reference

If you use Justitia in your research, please cite the following paper:

> Erkam Uzun, Carter Yagemann, Simon Chung, Vladimir Kolesnikov, and Wenke Lee. 2021. "Cryptographic Key Derivation from Biometric Inferences for Remote Authentication". In Proceedings of the 2021 ACM Asia Conference on Computer and Communications Security (ASIA CCS '21). Association for Computing Machinery, New York, NY, USA, 629–643. https://doi.org/10.1145/3433210.3437512

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

* `EMB_DIR:` Path to the embeddings directory. An embedding array source, extracted with FaceNet, is included in the repo (`lfw_clean_embeddings.p` belongs to 50 people from `Labeled Faces in the Wild` dataset).
* `ENR_ID:` Index of the enrollment person (embedding label).
* `QUE_ID:` Index of the query person (embedding label).
* `LSH_BIT_LEN:` Length of LSH in bits.
* `MASK_PROB:` Noise cancellation masking probability.
* `NROF_SUB_BITS:` Number of bits subsampled in the fuzzy extractor.
* `FE_ERR_THR:` Number of error bits the fuzzy extractor can tolerate.

## Example

1. **Same person's biometrics on enrollment and recovery.**

```bash
python justitia.py lfw_clean_embeddings.p 5 5 128 0.7 64 9
```

Which outputs:

```bash
True Positive. secret: [27c5e300ff9a927b3aef3730c72b39ac] is locked with enrollment_id:5. recoveredSecret: [27c5e300ff9a927b3aef3730c72b39ac] is recovered with query_id: 5
```

2. **Different peoples's biometrics on enrollment (id 1) and recovery (id 2).**
```bash
python justitia.py lfw_clean_embeddings.p 1 2 128 0.7 64 9
```

Which outputs:

```bash
True Negative. secret: [082bfb35d04d81b89df889306866262f] is locked with enrollment_id:1. recoveredSecret: [None] is recovered with query_id: 2
```

## License

This project is licensed under the GPLv3 License - see the LICENSE file for details.