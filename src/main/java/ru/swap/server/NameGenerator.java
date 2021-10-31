package ru.swap.server;

import java.util.Calendar;
import java.util.Random;

public class NameGenerator {
    private static final int diffBetweenAtoZ = 25;
    private static final int charValueOfa = 97;
    private static String lastGeneratedName = "";
    static int length = 10;

    static char[] vowels = {'a', 'e', 'i', 'o', 'u'};

    private NameGenerator() {
    }

    public static String getName() {
        for (;;) {
            Random randomNumberGenerator = new Random(Calendar.getInstance()
                    .getTimeInMillis());

            char[] nameInCharArray = new char[length];

            for (int i = 0; i < length; i++) {
                if (positionIsOdd(i)) {
                    nameInCharArray[i] = getVowel(randomNumberGenerator);
                } else {
                    nameInCharArray[i] = getConsonant(randomNumberGenerator);
                }
            }
            nameInCharArray[0] = (char) Character
                    .toUpperCase(nameInCharArray[0]);

            String currentGeneratedName = new String(nameInCharArray);

            if (!currentGeneratedName.equals(lastGeneratedName)) {
                lastGeneratedName = currentGeneratedName;
                return currentGeneratedName;
            }
        }
    }

    private static boolean positionIsOdd(int i) {
        return i % 2 == 0;
    }

    private static char getConsonant(Random randomNumberGenerator) {
        for (;;) {
            char currentCharacter = (char) (randomNumberGenerator
                    .nextInt(diffBetweenAtoZ) + charValueOfa);
            if (currentCharacter == 'a' || currentCharacter == 'e'
                    || currentCharacter == 'i' || currentCharacter == 'o'
                    || currentCharacter == 'u')
                continue;
            else
                return currentCharacter;
        }
    }

    private static char getVowel(Random randomNumberGenerator) {
        return vowels[randomNumberGenerator.nextInt(vowels.length)];
    }
}
