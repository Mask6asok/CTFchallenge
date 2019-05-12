
#include<string>
#include<assert.h>
#include<stdio.h>
#include<iostream>
#include<vector>
using namespace std;

static const char* pzbase = "987654321ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
	int zero = 0;
	int length = 0;
	while (pbegin != pend && *pbegin == 0) {
		pbegin++;
		zero++;
	}
	int size = (pend - pbegin) * 138 / 100 + 1;
	vector <unsigned char> b58(size);
	while (pbegin != pend) {
		int carry = *pbegin;
		int i = 0;
		vector<unsigned char>::reverse_iterator it;
		for (it = b58.rbegin(); (carry != 0 || i < length) && (it != b58.rend()); it++, i++)
		{
			carry += 256 * (*it);
			*it = carry % 58;
			carry /= 58;
		}
		assert(carry == 0);
		length = i;
		pbegin++;
	}
	vector<unsigned char>::iterator it = b58.begin() + (size - length);
	while (it != b58.end() && *it == 0)
		it++;
	string str;
	str.reserve(zero + (b58.end() - it));
	str.assign(zero, '1');
	while (it != b58.end())
		str += pzbase[*(it++)];
	return str;
}

bool DecodeBase58(const char* psz, std::vector<unsigned char>& vch)
{
	// Skip leading spaces.
	while (*psz && isspace(*psz))
		psz++;
	// Skip and count leading '1's.
	int zeroes = 0;
	int length = 0;
	while (*psz == '1') {
		zeroes++;
		psz++;
	}
	// Allocate enough space in big-endian base256 representation.
	int size = strlen(psz) * 733 / 1000 + 1; // log(58) / log(256), rounded up.
	std::vector<unsigned char> b256(size);
	// Process the characters.
	while (*psz && !isspace(*psz)) {
		// Decode base58 character
		const char* ch = strchr(pzbase, *psz);
		if (ch == nullptr)
			return false;
		// Apply "b256 = b256 * 58 + ch".
		int carry = ch - pzbase;
		int i = 0;
		for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
			carry += 58 * (*it);
			*it = carry % 256;
			carry /= 256;
		}
		assert(carry == 0);
		length = i;
		psz++;
	}
	// Skip trailing spaces.
	while (isspace(*psz))
		psz++;
	if (*psz != 0)
		return false;
	// Skip leading zeroes in b256.
	std::vector<unsigned char>::iterator it = b256.begin() + (size - length);
	while (it != b256.end() && *it == 0)
		it++;
	// Copy result into output vector.
	vch.reserve(zeroes + (b256.end() - it));
	vch.assign(zeroes, 0x00);
	while (it != b256.end())
		vch.push_back(*(it++));
	return true;
}

int main()
{
	string input;
	vector<unsigned char> str;
	cout << "input flag:" << endl;
	cin >> input;
	for (int i = 0; i < input.size(); i++) {
		str.push_back(input[i]);
	}

	/*
	str.push_back('N');
	str.push_back('J');
	str.push_back('U');
	str.push_back('S');
	str.push_back('T');
	str.push_back('.');
	str.push_back('b');
	str.push_back('a');
	str.push_back('b');
	str.push_back('y');
	str.push_back('r');
	str.push_back('e');
	*/
	string encode = EncodeBase58(str.data(), str.data() + str.size());
	vector<unsigned char> decode;
	cout << '1' << endl;
	cout << encode << endl;
//	DecodeBase58(encode.c_str(), decode);
	string results = "BnwU1ayEGksXUy4kuT6vPD";
	if (results == encode) {
		cout << "true";
	}
	return 0;
}