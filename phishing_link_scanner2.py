import tldextract
import Levenshtein

# List of trusted domains
TRUSTED_DOMAINS = {'example.com', 'google.com', 'facebook.com'}

# Test URLs to check
TEST_URLS = [
    'http://example.co',
    'http://examp1e.com',
    'https://www.google.security-update.com',
    'https://google.com'
]

def get_parts_of_domain(url: str) -> tuple[str, str, str]:
    """
    Extract the subdomain, domain, and suffix from a given URL.
    """
    domain_part = tldextract.extract(url)
    return domain_part.subdomain, domain_part.domain, domain_part.suffix

def is_misspelled_domain(domain: str, trusted_domains: set[str], threshold: float = 0.9) -> bool:
    """
    Check if the given domain is a misspelled version of any trusted domain.
    """
    for trusted_domain in trusted_domains:
        similarity = Levenshtein.ratio(domain, trusted_domain)
        if similarity >= threshold:
            return False  # Domain matches closely to a trusted domain
    return True

def check_phishing_url(url: str, trusted_domains: set[str], threshold: float = 0.9) -> tuple[bool, str]:
    """
    Check if a URL is potentially phishing based on domain similarity.
    """
    subdomain, domain, suffix = get_parts_of_domain(url)
    full_domain = f"{domain}.{suffix}"

    # Check if the domain is trusted
    if full_domain in trusted_domains:
        return False, "Safe"

    # Check for potential misspelling
    if is_misspelled_domain(domain, trusted_domains, threshold):
        return True, "Phishing"

    return False, "Safe"

def main():
    """
    Main function to analyze a list of URLs and detect potential phishing attempts.
    """
    phishing_results = []

    # Process each URL
    for url in TEST_URLS:
        is_phishing, status = check_phishing_url(url, TRUSTED_DOMAINS)
        result = {"URL": url, "Status": status}
        phishing_results.append(result)
    
    # Display results
    print("\n--- Phishing URL Detection Results ---")
    for result in phishing_results:
        print(f"URL: {result['URL']} -> Status: {result['Status']}")

if __name__ == "__main__":
    main()
