package com.deepwarden.app.di

import android.content.Context
import androidx.room.Room
import com.deepwarden.app.data.db.DeepWardenDatabase
import com.deepwarden.app.data.db.ScanDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Hilt wiring. Most classes are constructor-injected @Singletons;
 * only Room needs explicit providers.
 */
@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): DeepWardenDatabase =
        Room.databaseBuilder(context, DeepWardenDatabase::class.java, "deepwarden.db")
            // Scan history is a cache of observations, not user data — a schema
            // bump may safely rebuild it rather than block the user on migration.
            .fallbackToDestructiveMigration()
            .build()

    @Provides
    fun provideScanDao(db: DeepWardenDatabase): ScanDao = db.scanDao()
}
