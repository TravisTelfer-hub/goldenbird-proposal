encrypt:
	python3 scripts/encrypt/encrypt_public.py

encrypt-changed:
	python3 scripts/encrypt/encrypt_public.py --skip-unchanged

encrypt-show:
	python3 scripts/encrypt/encrypt_public.py --show

release-check:
	python3 .github/scripts/check-release.py --root public --manifest release-manifest.json

release-plan:
	python3 .github/scripts/check-release.py --root public --manifest release-manifest.json --plan
